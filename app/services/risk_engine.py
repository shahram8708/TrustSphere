"""Continuous risk scoring service for TrustSphere sessions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import math
import statistics
import sys
import time

from app.extensions import db


@dataclass
class CREResult:
    """Result returned by the Continuous Risk Engine."""

    risk_score: int
    risk_category: str
    contributing_factors: dict
    recommended_action: str
    processing_ms: int
    policy_overrides_applied: list[str] = field(default_factory=list)
    session_id: str | None = None
    event_id: str | None = None


class ContinuousRiskEngine:
    """Evaluate session context and produce a normalized identity risk score."""

    WEIGHT_DEVICE = 0.25
    WEIGHT_BEHAVIOURAL = 0.20
    WEIGHT_GEOGRAPHIC = 0.15
    WEIGHT_NETWORK = 0.15
    WEIGHT_TRANSACTION = 0.15
    WEIGHT_TIME_PATTERN = 0.10

    DEFAULT_THRESHOLDS = {
        "threshold_low": 30,
        "threshold_medium": 60,
        "threshold_high": 80,
    }

    DEFAULT_WEIGHTS = {
        "device_trust": WEIGHT_DEVICE,
        "behavioural_deviation": WEIGHT_BEHAVIOURAL,
        "geo_velocity": WEIGHT_GEOGRAPHIC,
        "network_reputation": WEIGHT_NETWORK,
        "transaction_anomaly": WEIGHT_TRANSACTION,
        "time_pattern": WEIGHT_TIME_PATTERN,
    }

    @classmethod
    def evaluate(
        cls,
        user_id,
        session_id,
        event_type,
        context_dict,
        institution_id=None,
    ):
        """Evaluate a user event and persist the resulting risk event."""
        start_time = time.time()
        context_dict = dict(context_dict or {})

        try:
            from app.models import RiskEvent, RiskPolicy, SessionRecord, User

            user = User.query.get(user_id)
            if not user:
                return cls._safe_result(start_time, session_id=session_id)

            policy = (
                RiskPolicy.query.filter_by(
                    institution_id=user.institution_id,
                    is_active=True,
                ).first()
            )
            weights = cls._weights_for_policy(policy)

            if context_dict.get("ip_address") and not context_dict.get("ip_country"):
                cls._hydrate_ip_context(context_dict)

            factors = {
                "device_trust": cls._compute_device_signal(
                    user.id,
                    context_dict.get("device_fingerprint_hash"),
                    context_dict,
                ),
                "behavioural_deviation": cls._compute_behavioural_signal(
                    user.id,
                    context_dict.get("behavioural_vector"),
                ),
                "geo_velocity": cls._compute_geographic_signal(
                    user.id,
                    context_dict.get("ip_country"),
                    context_dict.get("ip_city"),
                    session_id,
                ),
                "network_reputation": cls._compute_network_signal(
                    context_dict.get("ip_address"),
                ),
                "transaction_anomaly": cls._compute_transaction_signal(
                    user.id,
                    event_type,
                    context_dict,
                ),
                "time_pattern": cls._compute_time_signal(
                    user.id,
                    context_dict.get("current_hour"),
                ),
            }

            raw_score = sum(weights[key] * factors[key] for key in cls.DEFAULT_WEIGHTS)
            normalized = int(round(100 / (1 + math.exp(-6 * (raw_score - 50) / 50))))
            normalized, overrides = cls._apply_policy_overrides(
                normalized,
                context_dict,
                policy,
            )
            normalized = max(0, min(100, int(normalized)))

            # Preserve previously recorded user risk to avoid single-event drops.
            # Use a conservative strategy: do not reduce stored risk on evaluation.
            risk_before = int(user.risk_score_current or 0)
            risk_after = max(risk_before, normalized)

            # Compute category/action based on the final effective risk used by the platform.
            category = cls.get_risk_category_for_score(risk_after, user.institution_id)
            action = cls._recommended_action(category, event_type)

            session = SessionRecord.query.get(session_id) if session_id else None
            if session and (
                session.user_id != user.id
                or session.institution_id != (institution_id or user.institution_id)
            ):
                session = None
                session_id = None
            if not session:
                session = SessionRecord(
                    user_id=user.id,
                    institution_id=institution_id or user.institution_id,
                    ip_address=context_dict.get("ip_address"),
                    ip_country=context_dict.get("ip_country"),
                    ip_city=context_dict.get("ip_city"),
                    channel=context_dict.get("channel", "api"),
                    risk_score_initial=risk_before,
                    risk_score_peak=risk_after,
                    risk_score_final=risk_after,
                    stepup_triggered=action == "stepup",
                    stepup_outcome="pending" if action == "stepup" else "none",
                )
                db.session.add(session)
                db.session.flush()
                session_id = session.id
            else:
                session.risk_score_peak = max(session.risk_score_peak or 0, risk_after)
                session.risk_score_final = risk_after
                if action == "stepup":
                    session.stepup_triggered = True
                    session.stepup_outcome = "pending"
                if action == "block":
                    session.is_flagged = True
                db.session.add(session)

            processing_ms = int((time.time() - start_time) * 1000)
            risk_event = RiskEvent(
                session_id=session_id,
                institution_id=institution_id or user.institution_id,
                event_type=event_type,
                risk_score_before=risk_before,
                risk_score_after=risk_after,
                contributing_factors=json.dumps(factors, sort_keys=True),
                cre_response_action=action,
                event_metadata=json.dumps(context_dict, sort_keys=True, default=str),
                evaluated_at=datetime.utcnow(),
                processing_ms=processing_ms,
            )

            # Only update the stored user risk when it increases (avoid single-event drops).
            if risk_after > risk_before:
                user.risk_score_current = risk_after
                user.risk_score_updated_at = datetime.utcnow()
            user.last_active_at = datetime.utcnow()

            db.session.add(risk_event)
            db.session.add(user)
            db.session.flush()
            event_id = risk_event.id
            db.session.commit()

            if action == "block":
                cls._create_block_alert(
                    institution_id or user.institution_id,
                    user.id,
                    session_id,
                    event_type,
                    risk_after,
                )

            return CREResult(
                risk_score=risk_after,
                risk_category=category,
                contributing_factors=factors,
                recommended_action=action,
                processing_ms=int((time.time() - start_time) * 1000),
                policy_overrides_applied=overrides,
                session_id=session_id,
                event_id=event_id,
            )
        except Exception as exc:
            db.session.rollback()
            print(f"[ContinuousRiskEngine] Evaluation failed: {exc}", file=sys.stderr)
            return cls._safe_result(start_time, session_id=session_id)

    @classmethod
    def _safe_result(cls, start_time, session_id=None):
        return CREResult(
            risk_score=50,
            risk_category="Medium",
            contributing_factors={
                "device_trust": 50,
                "behavioural_deviation": 30,
                "geo_velocity": 20,
                "network_reputation": 20,
                "transaction_anomaly": 0,
                "time_pattern": 15,
            },
            recommended_action="monitor",
            processing_ms=int((time.time() - start_time) * 1000),
            policy_overrides_applied=[],
            session_id=session_id,
            event_id=None,
        )

    @classmethod
    def _weights_for_policy(cls, policy):
        weights = dict(cls.DEFAULT_WEIGHTS)
        config = cls._policy_json(policy, "ml_weight_config", {})
        aliases = {
            "device_trust": ("device_trust", "device"),
            "behavioural_deviation": (
                "behavioural_deviation",
                "behaviour",
                "behavioural",
            ),
            "geo_velocity": ("geo_velocity", "geographic", "location"),
            "network_reputation": ("network_reputation", "network"),
            "transaction_anomaly": ("transaction_anomaly", "transaction"),
            "time_pattern": ("time_pattern", "time"),
        }

        for target_key, source_keys in aliases.items():
            for source_key in source_keys:
                if source_key in config:
                    try:
                        weights[target_key] = max(float(config[source_key]), 0.0)
                    except (TypeError, ValueError):
                        continue
                    break

        total = sum(weights.values())
        if total <= 0:
            return dict(cls.DEFAULT_WEIGHTS)
        return {key: value / total for key, value in weights.items()}

    @classmethod
    def _policy_json(cls, policy, field_name, fallback):
        if not policy:
            return fallback
        method_name = {
            "stepup_rules": "get_stepup_rules_list",
            "ml_weight_config": "get_ml_weight_config",
        }.get(field_name)
        if method_name and hasattr(policy, method_name):
            try:
                value = getattr(policy, method_name)()
                if isinstance(value, type(fallback)):
                    return value
            except Exception:
                return fallback
        raw_value = getattr(policy, field_name, None)
        if not raw_value:
            return fallback
        try:
            value = json.loads(raw_value)
            return value if isinstance(value, type(fallback)) else fallback
        except (TypeError, json.JSONDecodeError):
            return fallback

    @classmethod
    def _hydrate_ip_context(cls, context_dict):
        try:
            from app.utils.ip_intel import get_ip_info

            info = get_ip_info(context_dict.get("ip_address"))
            context_dict.setdefault("ip_country", info.get("country"))
            context_dict.setdefault("ip_city", info.get("city"))
        except Exception as exc:
            print(f"[ContinuousRiskEngine] IP context lookup failed: {exc}", file=sys.stderr)

    @classmethod
    def _apply_policy_overrides(cls, score, context_dict, policy):
        overrides = []
        if context_dict.get("watchlist_match") is True:
            score += 20
            overrides.append("Watchlist match +20")
        if context_dict.get("stepup_previously_failed") is True:
            score += 15
            overrides.append("Previous step up failure +15")
        if context_dict.get("is_account_recovery") is True:
            score += 10
            overrides.append("Account recovery context +10")

        channel = context_dict.get("channel")
        channel_policies = cls._policy_json(policy, "channel_policies", {})
        channel_policy = channel_policies.get(channel) if isinstance(channel_policies, dict) else None
        if isinstance(channel_policy, dict):
            try:
                boost = int(channel_policy.get("risk_boost", 0))
            except (TypeError, ValueError):
                boost = 0
            if boost:
                score += boost
                overrides.append(f"Channel policy boost +{boost}")
            if channel_policy.get("service_token_required") and not context_dict.get("service_token_valid"):
                score += 5
                overrides.append("Missing service token +5")
        elif channel_policy == "strict" and not context_dict.get("service_token_valid"):
            score += 5
            overrides.append("Strict channel policy +5")

        return max(0, min(100, score)), overrides

    @classmethod
    def _recommended_action(cls, category, event_type):
        if category == "Low":
            return "allow"
        if category == "Medium":
            return "monitor"
        if category == "High":
            return "stepup"
        if event_type in {"transaction", "data_export"}:
            return "block"
        return "stepup"

    @classmethod
    def _create_block_alert(cls, institution_id, user_id, session_id, event_type, risk_score):
        try:
            from app.services.alert_manager import AlertManager

            alert_type = "bulk_export" if event_type == "data_export" else "suspicious_behaviour"
            title = "Critical risk action blocked"
            description = (
                f"The risk engine recommended a block for {event_type} "
                f"with risk score {risk_score}."
            )
            AlertManager.create_alert(
                institution_id=institution_id,
                user_id=user_id,
                session_id=session_id,
                alert_type=alert_type,
                severity="critical",
                title=title,
                description=description,
                auto_action="block",
            )
        except Exception as exc:
            print(f"[ContinuousRiskEngine] Block alert failed: {exc}", file=sys.stderr)

    @classmethod
    def _compute_device_signal(cls, user_id, device_fingerprint_hash, context_dict):
        try:
            if not device_fingerprint_hash:
                return 40
            from app.models import Device

            device = Device.query.filter_by(
                user_id=user_id,
                device_fingerprint_hash=device_fingerprint_hash,
                is_removed=False,
            ).first()
            if device:
                score = int(device.get_trust_score())
            else:
                context_dict["new_device_detected"] = True
                score = 65
            if context_dict.get("is_emulator") is True:
                score += 10
            if context_dict.get("is_rooted") is True:
                score += 10
            return max(0, min(100, int(score)))
        except Exception as exc:
            print(f"[ContinuousRiskEngine] Device signal failed: {exc}", file=sys.stderr)
            return 40

    @classmethod
    def _compute_behavioural_signal(cls, user_id, behavioural_vector):
        try:
            if not behavioural_vector:
                return 30
            from app.models import BehaviouralProfile

            profile = BehaviouralProfile.query.filter_by(user_id=user_id, is_active=True).first()
            if not profile or profile.confidence_level == "low":
                return 30
            return max(0, min(100, int(profile.compute_similarity_score(behavioural_vector))))
        except Exception as exc:
            print(f"[ContinuousRiskEngine] Behavioural signal failed: {exc}", file=sys.stderr)
            return 30

    @classmethod
    def _compute_geographic_signal(cls, user_id, ip_country, ip_city, session_id):
        try:
            if not ip_country:
                return 20
            from app.models import SessionRecord

            query = SessionRecord.query.filter(SessionRecord.user_id == user_id)
            if session_id:
                query = query.filter(SessionRecord.id != session_id)
            recent_sessions = (
                query.order_by(SessionRecord.started_at.desc())
                .limit(5)
                .all()
            )
            one_hour_ago = datetime.utcnow() - timedelta(hours=1)
            for session in recent_sessions:
                if (
                    session.started_at
                    and session.started_at >= one_hour_ago
                    and session.ip_country
                    and session.ip_country != ip_country
                ):
                    return 90

            countries = {session.ip_country for session in recent_sessions if session.ip_country}
            city_pairs = {
                (session.ip_country, session.ip_city)
                for session in recent_sessions
                if session.ip_country and session.ip_city
            }
            if (ip_country, ip_city) in city_pairs:
                return 0
            if ip_country not in countries and ip_country != "IN":
                return 40
            if ip_country == "IN" and (ip_country, ip_city) not in city_pairs:
                return 15
            return 10
        except Exception as exc:
            print(f"[ContinuousRiskEngine] Geographic signal failed: {exc}", file=sys.stderr)
            return 20

    @classmethod
    def _compute_network_signal(cls, ip_address):
        try:
            if not ip_address:
                return 20
            from app.utils.ip_intel import get_ip_info

            result = get_ip_info(ip_address)
            if result.get("is_tor"):
                return 90
            if result.get("is_vpn") or result.get("is_proxy"):
                return 65
            return max(0, min(100, int(result.get("risk_score", 20))))
        except Exception as exc:
            print(f"[ContinuousRiskEngine] Network signal failed: {exc}", file=sys.stderr)
            return 20

    @classmethod
    def _compute_transaction_signal(cls, user_id, event_type, context_dict):
        try:
            if event_type not in {"transaction", "data_export"}:
                return 0

            if event_type == "data_export":
                export_volume_kb = int(context_dict.get("export_volume_kb") or 0)
                score = 40
                if export_volume_kb > 5000:
                    score += 40
                elif export_volume_kb > 1000:
                    score += 20
                return max(0, min(100, score))

            transaction_amount = context_dict.get("transaction_amount")
            if transaction_amount is None:
                return 10
            transaction_amount = float(transaction_amount)

            from app.models import RiskEvent, SessionRecord

            historical_events = (
                RiskEvent.query.join(SessionRecord)
                .filter(
                    SessionRecord.user_id == user_id,
                    RiskEvent.event_type == "transaction",
                )
                .order_by(RiskEvent.evaluated_at.desc())
                .limit(20)
                .all()
            )
            historical_amounts = []
            for event in historical_events:
                metadata = event.get_event_metadata_dict()
                amount = metadata.get("transaction_amount", metadata.get("amount_inr"))
                try:
                    if amount is not None:
                        historical_amounts.append(float(amount))
                except (TypeError, ValueError):
                    continue

            if not historical_amounts:
                score = 25
            else:
                average_amount = statistics.mean(historical_amounts)
                score = 70 if average_amount > 0 and transaction_amount > 5 * average_amount else 10

            if context_dict.get("is_new_beneficiary") is True:
                score += 30
            return max(0, min(100, int(score)))
        except Exception as exc:
            print(f"[ContinuousRiskEngine] Transaction signal failed: {exc}", file=sys.stderr)
            return 10

    @classmethod
    def _compute_time_signal(cls, user_id, current_hour):
        try:
            if current_hour is None:
                current_hour = datetime.utcnow().hour
            current_hour = int(current_hour)

            from app.models import SessionRecord

            sessions = (
                SessionRecord.query.filter_by(user_id=user_id)
                .order_by(SessionRecord.started_at.desc())
                .limit(30)
                .all()
            )
            hours = [session.started_at.hour for session in sessions if session.started_at]
            if len(hours) < 5:
                return 15
            mean_hour = statistics.mean(hours)
            stdev_hour = statistics.stdev(hours)
            if stdev_hour == 0:
                return 0 if current_hour == int(round(mean_hour)) else 75
            z_score = abs(current_hour - mean_hour) / stdev_hour
            if z_score < 1.0:
                return 0
            if z_score < 2.0:
                return 25
            if z_score < 3.0:
                return 50
            return 75
        except Exception as exc:
            print(f"[ContinuousRiskEngine] Time signal failed: {exc}", file=sys.stderr)
            return 15

    @classmethod
    def get_risk_category_for_score(cls, score, institution_id=None):
        """Return a risk category for a score using the active institutional policy."""
        try:
            thresholds = dict(cls.DEFAULT_THRESHOLDS)
            if institution_id:
                from app.models import RiskPolicy

                policy = RiskPolicy.query.filter_by(
                    institution_id=institution_id,
                    is_active=True,
                ).first()
                if policy:
                    thresholds = {
                        "threshold_low": policy.threshold_low,
                        "threshold_medium": policy.threshold_medium,
                        "threshold_high": policy.threshold_high,
                    }
            score = int(score or 0)
            if score <= thresholds["threshold_low"]:
                return "Low"
            if score <= thresholds["threshold_medium"]:
                return "Medium"
            if score <= thresholds["threshold_high"]:
                return "High"
            return "Critical"
        except Exception as exc:
            print(f"[ContinuousRiskEngine] Category lookup failed: {exc}", file=sys.stderr)
            return "Medium"

    @classmethod
    def get_contributing_factors_summary(cls, factors_dict):
        """Return human readable factor summaries sorted by highest contribution."""
        try:
            labels = {
                "device_trust": "Device",
                "behavioural_deviation": "Behaviour",
                "geo_velocity": "Geographic",
                "network_reputation": "Network",
                "transaction_anomaly": "Transaction",
                "time_pattern": "Time Pattern",
            }
            descriptions = {
                "device_trust": "Device trust risk",
                "behavioural_deviation": "Behavioural deviation",
                "geo_velocity": "Location anomaly",
                "network_reputation": "Network reputation",
                "transaction_anomaly": "Transaction anomaly",
                "time_pattern": "Unusual time",
            }
            items = []
            for key, value in (factors_dict or {}).items():
                try:
                    score = int(value)
                except (TypeError, ValueError):
                    score = 0
                label = labels.get(key, key.replace("_", " ").title())
                description = descriptions.get(key, label)
                items.append((score, f"{label}: {description} ({score})"))
            return [item[1] for item in sorted(items, key=lambda item: item[0], reverse=True)]
        except Exception as exc:
            print(f"[ContinuousRiskEngine] Factor summary failed: {exc}", file=sys.stderr)
            return []
