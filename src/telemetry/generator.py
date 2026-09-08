"""High-fidelity synthetic enterprise data generator for ApexGlobal Financial Corp."""

from datetime import datetime, timezone, timedelta
import random
from typing import Any, Dict, List, Optional, Tuple
from src.assets.graph import EnterpriseDependencyGraph
from src.assets.models import (
    AssetRecord,
    AssetType,
    BusinessService,
    DataSensitivityTier,
    EnvironmentTier,
)
from src.assets.scoring import (
    calculate_asset_criticality_score,
    calculate_asset_financial_valuation,
)
from src.telemetry.models import (
    CloudProvider,
    CspmFinding,
    EdrStatus,
    EdrTelemetryFinding,
    ExploitMaturity,
    IamFinding,
    NormalizedFinding,
    SeverityLevel,
    SiemAlertFinding,
    SiemAlertType,
    TelemetryDomain,
    VulnerabilityFinding,
)
from src.telemetry.normalizer import TelemetryNormalizer


class ApexEnterpriseGenerator:
    """
    Generates high-fidelity, deterministic synthetic enterprise assets and multi-domain
    security telemetry for ApexGlobal Financial Corp.
    Total: 65 enterprise assets across 5 Business Units.
    """

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self.rng = random.Random(seed)

    def generate_business_services(self) -> List[BusinessService]:
        """Creates the core revenue-generating business services for ApexGlobal Financial Corp."""
        return [
            BusinessService(
                service_id="SVC-SWIFT-SETTLE",
                name="SWIFT Global Wire Settlement",
                business_unit="Payment Services",
                revenue_per_hour_downtime=1_200_000.0,
                criticality=1.0,
                description="Real-time gross cross-border institutional wire settlements",
            ),
            BusinessService(
                service_id="SVC-PAY-GATEWAY",
                name="Core Merchant Payment Gateway",
                business_unit="Payment Services",
                revenue_per_hour_downtime=850_000.0,
                criticality=0.98,
                description="High-volume online merchant authorization and clearing switch",
            ),
            BusinessService(
                service_id="SVC-CARD-SWITCH",
                name="Debit & Credit Card Transaction Switch",
                business_unit="Payment Services",
                revenue_per_hour_downtime=650_000.0,
                criticality=0.95,
                description="POS and ATM transaction routing and cardholder verification",
            ),
            BusinessService(
                service_id="SVC-RETAIL-MOBILE",
                name="Retail Mobile Banking Application",
                business_unit="Retail Banking",
                revenue_per_hour_downtime=400_000.0,
                criticality=0.90,
                description="Consumer mobile banking, instant transfers (UPI/IMPS), and bill pay",
            ),
            BusinessService(
                service_id="SVC-RETAIL-PORTAL",
                name="Retail Internet Banking Web Portal",
                business_unit="Retail Banking",
                revenue_per_hour_downtime=250_000.0,
                criticality=0.85,
                description="Customer web banking portal and account management",
            ),
            BusinessService(
                service_id="SVC-WEALTH-ADVISORY",
                name="High Net Worth Wealth Advisory Platform",
                business_unit="Wealth Management",
                revenue_per_hour_downtime=350_000.0,
                criticality=0.88,
                description="HNW portfolio advisory, equity trading, and custody",
            ),
            BusinessService(
                service_id="SVC-ALGO-TRADING",
                name="Algorithmic Quantitative Execution Engine",
                business_unit="Wealth Management",
                revenue_per_hour_downtime=500_000.0,
                criticality=0.92,
                description="Low-latency automated algorithmic market execution",
            ),
            BusinessService(
                service_id="SVC-CLOUD-FABRIC",
                name="Enterprise API Cloud Integration Fabric",
                business_unit="Cloud Infrastructure",
                revenue_per_hour_downtime=300_000.0,
                criticality=0.85,
                description="Central Service Mesh and API Gateway routing all external traffic",
            ),
            BusinessService(
                service_id="SVC-CORP-ERP",
                name="Enterprise Financial ERP & Payroll",
                business_unit="Corporate IT",
                revenue_per_hour_downtime=100_000.0,
                criticality=0.70,
                description="Internal corporate financials, general ledger, and human resources",
            ),
        ]

    def generate_assets(self) -> List[AssetRecord]:
        """
        Generates exactly 65 enterprise assets across 5 Business Units:
          - Payment Services: 15 assets
          - Retail Banking: 14 assets
          - Wealth Management: 11 assets
          - Cloud Infrastructure: 15 assets
          - Corporate IT: 10 assets
        """
        assets: List[AssetRecord] = []

        # -------------------------------------------------------------------
        # 1. Payment Services (15 assets)
        # -------------------------------------------------------------------
        assets.append(
            AssetRecord(
                asset_id="PAY-DB-01",
                name="core-payment-oracle-db-prod-01",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.DATABASE,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=250_000.0,
                downtime_cost_per_hour=150_000.0,
                dependent_services=["SVC-SWIFT-SETTLE", "SVC-PAY-GATEWAY", "SVC-CARD-SWITCH"],
                hostname="db-pay-cluster01.internal.apexglobal.net",
                ip_address="10.10.4.11",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-DB-02",
                name="core-payment-oracle-db-prod-02",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.DATABASE,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=250_000.0,
                downtime_cost_per_hour=100_000.0,
                dependent_services=["SVC-SWIFT-SETTLE", "SVC-PAY-GATEWAY"],
                hostname="db-pay-cluster02.internal.apexglobal.net",
                ip_address="10.10.4.12",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-SWIFT-GW-01",
                name="swift-alliance-gateway-prod-01",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=120_000.0,
                downtime_cost_per_hour=50_000.0,
                dependent_services=["SVC-SWIFT-SETTLE"],
                hostname="swift-gw-01.internal.apexglobal.net",
                ip_address="10.10.4.21",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-CARD-AUTH-01",
                name="card-auth-switch-service-01",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.CONTAINER,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=30_000.0,
                downtime_cost_per_hour=40_000.0,
                dependent_services=["SVC-CARD-SWITCH"],
                hostname="k8s-pod-cardauth-01",
                ip_address="10.10.4.31",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-CARD-AUTH-02",
                name="card-auth-switch-service-02",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.CONTAINER,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=30_000.0,
                downtime_cost_per_hour=40_000.0,
                dependent_services=["SVC-CARD-SWITCH"],
                hostname="k8s-pod-cardauth-02",
                ip_address="10.10.4.32",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-API-GW-01",
                name="merchant-api-gateway-prod-01",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.API_GATEWAY,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=45_000.0,
                downtime_cost_per_hour=35_000.0,
                dependent_services=["SVC-PAY-GATEWAY"],
                hostname="api-pay.apexglobal.com",
                ip_address="198.51.100.10",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-HSM-CLUSTER-01",
                name="thales-luna-payment-hsm-cluster",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=180_000.0,
                downtime_cost_per_hour=80_000.0,
                dependent_services=["SVC-CARD-SWITCH", "SVC-SWIFT-SETTLE"],
                hostname="hsm-cluster-01.internal.apexglobal.net",
                ip_address="10.10.4.5",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-CLEARING-APP-01",
                name="batch-clearing-engine-prod-01",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=40_000.0,
                downtime_cost_per_hour=25_000.0,
                dependent_services=["SVC-PAY-GATEWAY"],
                hostname="clearing-app-01.internal.apexglobal.net",
                ip_address="10.10.4.40",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-REDIS-CACHE-01",
                name="payment-session-redis-cache",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.DATABASE,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=15_000.0,
                downtime_cost_per_hour=15_000.0,
                dependent_services=["SVC-PAY-GATEWAY"],
                hostname="redis-pay-01.internal.apexglobal.net",
                ip_address="10.10.4.50",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-KAFKA-BROKER-01",
                name="payment-events-kafka-broker-01",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=25_000.0,
                downtime_cost_per_hour=30_000.0,
                dependent_services=["SVC-PAY-GATEWAY", "SVC-CARD-SWITCH"],
                hostname="kafka-pay-01.internal.apexglobal.net",
                ip_address="10.10.4.61",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-S3-ARCHIVE-01",
                name="arn:aws:s3:::apex-payment-reconciliation-archive",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.S3_BUCKET,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=50_000.0,
                downtime_cost_per_hour=10_000.0,
                dependent_services=["SVC-PAY-GATEWAY"],
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-STG-APP-01",
                name="payment-staging-app-server",
                business_unit="Payment Services",
                environment=EnvironmentTier.STAGING,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=15_000.0,
                downtime_cost_per_hour=1_000.0,
                dependent_services=[],
                hostname="pay-stg-01.internal.apexglobal.net",
                ip_address="10.10.14.10",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-DEV-APP-01",
                name="payment-dev-microservice-node",
                business_unit="Payment Services",
                environment=EnvironmentTier.DEVELOPMENT,
                asset_type=AssetType.CONTAINER,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=5_000.0,
                downtime_cost_per_hour=0.0,
                dependent_services=[],
                hostname="k8s-pod-paydev-01",
                ip_address="10.10.24.11",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-ADMIN-JUMP-01",
                name="payment-ops-bastion-host",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.ENDPOINT,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=8_000.0,
                downtime_cost_per_hour=5_000.0,
                dependent_services=["SVC-PAY-GATEWAY"],
                hostname="bastion-pay.internal.apexglobal.net",
                ip_address="10.10.4.200",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="PAY-MONITOR-01",
                name="payment-prometheus-monitoring-host",
                business_unit="Payment Services",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=10_000.0,
                downtime_cost_per_hour=2_000.0,
                dependent_services=[],
                hostname="prom-pay-01.internal.apexglobal.net",
                ip_address="10.10.4.250",
            )
        )

        # -------------------------------------------------------------------
        # 2. Retail Banking (14 assets)
        # -------------------------------------------------------------------
        assets.append(
            AssetRecord(
                asset_id="RET-DB-CUSTOMER-01",
                name="retail-customer-profile-db-prod",
                business_unit="Retail Banking",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.DATABASE,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=200_000.0,
                downtime_cost_per_hour=80_000.0,
                dependent_services=["SVC-RETAIL-MOBILE", "SVC-RETAIL-PORTAL"],
                hostname="db-ret-cust01.internal.apexglobal.net",
                ip_address="10.10.1.11",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-APP-MOBILE-01",
                name="retail-mobile-api-backend-01",
                business_unit="Retail Banking",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.CONTAINER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=25_000.0,
                downtime_cost_per_hour=50_000.0,
                dependent_services=["SVC-RETAIL-MOBILE"],
                hostname="k8s-pod-retmobile-01",
                ip_address="10.10.1.31",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-APP-MOBILE-02",
                name="retail-mobile-api-backend-02",
                business_unit="Retail Banking",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.CONTAINER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=25_000.0,
                downtime_cost_per_hour=50_000.0,
                dependent_services=["SVC-RETAIL-MOBILE"],
                hostname="k8s-pod-retmobile-02",
                ip_address="10.10.1.32",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-WEB-PORTAL-01",
                name="retail-banking-web-frontend-01",
                business_unit="Retail Banking",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=30_000.0,
                downtime_cost_per_hour=35_000.0,
                dependent_services=["SVC-RETAIL-PORTAL"],
                hostname="banking.apexglobal.com",
                ip_address="198.51.100.20",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-S3-KYC-01",
                name="arn:aws:s3:::apex-retail-customer-kyc-documents",
                business_unit="Retail Banking",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.S3_BUCKET,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=100_000.0,
                downtime_cost_per_hour=20_000.0,
                dependent_services=["SVC-RETAIL-MOBILE", "SVC-RETAIL-PORTAL"],
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-BILLPAY-SRV-01",
                name="retail-billpay-integrator-01",
                business_unit="Retail Banking",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=20_000.0,
                downtime_cost_per_hour=15_000.0,
                dependent_services=["SVC-RETAIL-MOBILE"],
                hostname="billpay-01.internal.apexglobal.net",
                ip_address="10.10.1.45",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-AUTH-SERVICE-01",
                name="retail-customer-auth0-connector",
                business_unit="Retail Banking",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.CONTAINER,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=25_000.0,
                downtime_cost_per_hour=60_000.0,
                dependent_services=["SVC-RETAIL-MOBILE", "SVC-RETAIL-PORTAL"],
                hostname="k8s-pod-retauth-01",
                ip_address="10.10.1.55",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-API-GATEWAY-01",
                name="retail-external-api-gateway",
                business_unit="Retail Banking",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.API_GATEWAY,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=35_000.0,
                downtime_cost_per_hour=30_000.0,
                dependent_services=["SVC-RETAIL-MOBILE"],
                hostname="api-retail.apexglobal.com",
                ip_address="198.51.100.25",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-NOTIFY-SRV-01",
                name="sms-email-notification-dispatcher",
                business_unit="Retail Banking",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=15_000.0,
                downtime_cost_per_hour=5_000.0,
                dependent_services=[],
                hostname="notify-01.internal.apexglobal.net",
                ip_address="10.10.1.70",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-STG-PORTAL-01",
                name="retail-banking-staging-portal",
                business_unit="Retail Banking",
                environment=EnvironmentTier.STAGING,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=12_000.0,
                downtime_cost_per_hour=1_000.0,
                dependent_services=[],
                hostname="stg-banking.internal.apexglobal.net",
                ip_address="10.10.11.20",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-DEV-K8S-01",
                name="retail-dev-k8s-worker-node",
                business_unit="Retail Banking",
                environment=EnvironmentTier.DEVELOPMENT,
                asset_type=AssetType.CONTAINER,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=6_000.0,
                downtime_cost_per_hour=0.0,
                dependent_services=[],
                hostname="ret-k8s-dev-01",
                ip_address="10.10.21.30",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-BRANCH-WS-01",
                name="retail-branch-teller-terminal-01",
                business_unit="Retail Banking",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.ENDPOINT,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=3_500.0,
                downtime_cost_per_hour=1_000.0,
                dependent_services=[],
                hostname="teller-ws-001.branch.apexglobal.net",
                ip_address="10.20.1.101",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-BRANCH-WS-02",
                name="retail-branch-teller-terminal-02",
                business_unit="Retail Banking",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.ENDPOINT,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=3_500.0,
                downtime_cost_per_hour=1_000.0,
                dependent_services=[],
                hostname="teller-ws-002.branch.apexglobal.net",
                ip_address="10.20.1.102",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="RET-ATM-GW-01",
                name="regional-atm-network-gateway-01",
                business_unit="Retail Banking",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=35_000.0,
                downtime_cost_per_hour=25_000.0,
                dependent_services=["SVC-RETAIL-MOBILE"],
                hostname="atm-gw-01.internal.apexglobal.net",
                ip_address="10.10.1.90",
            )
        )

        # -------------------------------------------------------------------
        # 3. Wealth Management (11 assets)
        # -------------------------------------------------------------------
        assets.append(
            AssetRecord(
                asset_id="WLT-DB-PORTFOLIO-01",
                name="wealth-portfolio-postgresql-cluster",
                business_unit="Wealth Management",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.DATABASE,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=150_000.0,
                downtime_cost_per_hour=90_000.0,
                dependent_services=["SVC-WEALTH-ADVISORY", "SVC-ALGO-TRADING"],
                hostname="db-wlt-port01.internal.apexglobal.net",
                ip_address="10.10.2.11",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="WLT-ALGO-ENGINE-01",
                name="algo-execution-cplusplus-engine-01",
                business_unit="Wealth Management",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=80_000.0,
                downtime_cost_per_hour=120_000.0,
                dependent_services=["SVC-ALGO-TRADING"],
                hostname="algo-srv-01.internal.apexglobal.net",
                ip_address="10.10.2.21",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="WLT-MARKET-FEED-01",
                name="bloomberg-reuters-market-data-feed",
                business_unit="Wealth Management",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=40_000.0,
                downtime_cost_per_hour=60_000.0,
                dependent_services=["SVC-ALGO-TRADING", "SVC-WEALTH-ADVISORY"],
                hostname="mkt-feed-01.internal.apexglobal.net",
                ip_address="10.10.2.35",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="WLT-ADVISORY-APP-01",
                name="wealth-advisor-portal-app",
                business_unit="Wealth Management",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.CONTAINER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=30_000.0,
                downtime_cost_per_hour=40_000.0,
                dependent_services=["SVC-WEALTH-ADVISORY"],
                hostname="k8s-pod-wltadv-01",
                ip_address="10.10.2.41",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="WLT-S3-STATEMENTS-01",
                name="arn:aws:s3:::apex-hnw-client-monthly-statements",
                business_unit="Wealth Management",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.S3_BUCKET,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=45_000.0,
                downtime_cost_per_hour=10_000.0,
                dependent_services=["SVC-WEALTH-ADVISORY"],
            )
        )
        assets.append(
            AssetRecord(
                asset_id="WLT-CLIENT-PORTAL-01",
                name="wealth-client-investor-portal",
                business_unit="Wealth Management",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=35_000.0,
                downtime_cost_per_hour=30_000.0,
                dependent_services=["SVC-WEALTH-ADVISORY"],
                hostname="wealth.apexglobal.com",
                ip_address="198.51.100.40",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="WLT-API-GATEWAY-01",
                name="wealth-fix-order-api-gateway",
                business_unit="Wealth Management",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.API_GATEWAY,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=40_000.0,
                downtime_cost_per_hour=50_000.0,
                dependent_services=["SVC-ALGO-TRADING"],
                hostname="fix-api.apexglobal.com",
                ip_address="198.51.100.45",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="WLT-STG-APP-01",
                name="wealth-staging-model-test-server",
                business_unit="Wealth Management",
                environment=EnvironmentTier.STAGING,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=15_000.0,
                downtime_cost_per_hour=1_000.0,
                dependent_services=[],
                hostname="wlt-stg-01.internal.apexglobal.net",
                ip_address="10.10.12.15",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="WLT-ANALYTICS-DB-01",
                name="wealth-snowflake-analytics-warehouse",
                business_unit="Wealth Management",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.DATABASE,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=60_000.0,
                downtime_cost_per_hour=15_000.0,
                dependent_services=[],
                hostname="dw-wlt-01.internal.apexglobal.net",
                ip_address="10.10.2.80",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="WLT-TRADER-WS-01",
                name="institutional-trading-desk-workstation-01",
                business_unit="Wealth Management",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.ENDPOINT,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=8_000.0,
                downtime_cost_per_hour=10_000.0,
                dependent_services=["SVC-ALGO-TRADING"],
                hostname="trader-ws-001.internal.apexglobal.net",
                ip_address="10.10.2.110",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="WLT-TRADER-WS-02",
                name="institutional-trading-desk-workstation-02",
                business_unit="Wealth Management",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.ENDPOINT,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=8_000.0,
                downtime_cost_per_hour=10_000.0,
                dependent_services=["SVC-ALGO-TRADING"],
                hostname="trader-ws-002.internal.apexglobal.net",
                ip_address="10.10.2.111",
            )
        )

        # -------------------------------------------------------------------
        # 4. Cloud Infrastructure (15 assets)
        # -------------------------------------------------------------------
        assets.append(
            AssetRecord(
                asset_id="CLOUD-K8S-PROD-CP",
                name="k8s-production-control-plane-master",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=100_000.0,
                downtime_cost_per_hour=150_000.0,
                dependent_services=["SVC-CLOUD-FABRIC", "SVC-PAY-GATEWAY", "SVC-RETAIL-MOBILE"],
                hostname="k8s-master-prod.internal.apexglobal.net",
                ip_address="10.10.0.10",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-K8S-WORKER-01",
                name="k8s-production-worker-node-01",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=30_000.0,
                downtime_cost_per_hour=50_000.0,
                dependent_services=["SVC-CLOUD-FABRIC"],
                hostname="k8s-node-01.internal.apexglobal.net",
                ip_address="10.10.0.21",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-K8S-WORKER-02",
                name="k8s-production-worker-node-02",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=30_000.0,
                downtime_cost_per_hour=50_000.0,
                dependent_services=["SVC-CLOUD-FABRIC"],
                hostname="k8s-node-02.internal.apexglobal.net",
                ip_address="10.10.0.22",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-IAM-VAULT-01",
                name="hashicorp-vault-secrets-cluster-prod",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=150_000.0,
                downtime_cost_per_hour=100_000.0,
                dependent_services=["SVC-CLOUD-FABRIC", "SVC-SWIFT-SETTLE", "SVC-PAY-GATEWAY"],
                hostname="vault-prod-01.internal.apexglobal.net",
                ip_address="10.10.0.50",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-INGRESS-PROXY-01",
                name="envoy-cloud-ingress-proxy-01",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.API_GATEWAY,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=40_000.0,
                downtime_cost_per_hour=80_000.0,
                dependent_services=["SVC-CLOUD-FABRIC"],
                hostname="ingress-01.apexglobal.com",
                ip_address="198.51.100.5",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-INGRESS-PROXY-02",
                name="envoy-cloud-ingress-proxy-02",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.API_GATEWAY,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=40_000.0,
                downtime_cost_per_hour=80_000.0,
                dependent_services=["SVC-CLOUD-FABRIC"],
                hostname="ingress-02.apexglobal.com",
                ip_address="198.51.100.6",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-LOG-OPENSEARCH-01",
                name="opensearch-central-logging-cluster",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.DATABASE,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=60_000.0,
                downtime_cost_per_hour=20_000.0,
                dependent_services=[],
                hostname="logs-es-01.internal.apexglobal.net",
                ip_address="10.10.0.70",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-AWS-ROOT-ACC",
                name="arn:aws:organizations::123456789012:account/apex-root",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=300_000.0,
                downtime_cost_per_hour=150_000.0,
                dependent_services=["SVC-CLOUD-FABRIC"],
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-S3-TERRAFORM-01",
                name="arn:aws:s3:::apex-terraform-remote-state-lock",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.S3_BUCKET,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=25_000.0,
                downtime_cost_per_hour=10_000.0,
                dependent_services=[],
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-SIEM-COLLECTOR-01",
                name="splunk-siem-forwarder-aggregator",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=45_000.0,
                downtime_cost_per_hour=15_000.0,
                dependent_services=[],
                hostname="siem-fwd-01.internal.apexglobal.net",
                ip_address="10.10.0.95",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-BASTION-JUMP-01",
                name="cloud-infra-teleport-bastion",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.ENDPOINT,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=15_000.0,
                downtime_cost_per_hour=15_000.0,
                dependent_services=["SVC-CLOUD-FABRIC"],
                hostname="teleport.internal.apexglobal.net",
                ip_address="10.10.0.120",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-STG-K8S-01",
                name="k8s-staging-cluster-node-01",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.STAGING,
                asset_type=AssetType.CONTAINER,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=15_000.0,
                downtime_cost_per_hour=1_000.0,
                dependent_services=[],
                hostname="k8s-stg-node-01",
                ip_address="10.10.10.21",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-DEV-K8S-01",
                name="k8s-development-cluster-node-01",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.DEVELOPMENT,
                asset_type=AssetType.CONTAINER,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=8_000.0,
                downtime_cost_per_hour=0.0,
                dependent_services=[],
                hostname="k8s-dev-node-01",
                ip_address="10.10.20.21",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-DNS-ROUTE53",
                name="apexglobal-route53-hosted-zones",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.PUBLIC,
                replacement_cost=20_000.0,
                downtime_cost_per_hour=40_000.0,
                dependent_services=["SVC-CLOUD-FABRIC"],
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CLOUD-BACKUP-VAULT-01",
                name="aws-backup-cross-region-vault",
                business_unit="Cloud Infrastructure",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.S3_BUCKET,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=75_000.0,
                downtime_cost_per_hour=25_000.0,
                dependent_services=[],
            )
        )

        # -------------------------------------------------------------------
        # 5. Corporate IT (10 assets)
        # -------------------------------------------------------------------
        assets.append(
            AssetRecord(
                asset_id="CORP-ERP-APP-01",
                name="sap-s4hana-corporate-erp-app",
                business_unit="Corporate IT",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=150_000.0,
                downtime_cost_per_hour=50_000.0,
                dependent_services=["SVC-CORP-ERP"],
                hostname="erp-app-01.internal.apexglobal.net",
                ip_address="10.10.3.10",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CORP-ERP-DB-01",
                name="sap-s4hana-hana-db-cluster",
                business_unit="Corporate IT",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.DATABASE,
                data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
                replacement_cost=200_000.0,
                downtime_cost_per_hour=60_000.0,
                dependent_services=["SVC-CORP-ERP"],
                hostname="db-hana-01.internal.apexglobal.net",
                ip_address="10.10.3.11",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CORP-AD-DC-01",
                name="active-directory-domain-controller-01",
                business_unit="Corporate IT",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=50_000.0,
                downtime_cost_per_hour=40_000.0,
                dependent_services=["SVC-CORP-ERP"],
                hostname="dc01.corp.apexglobal.net",
                ip_address="10.10.3.2",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CORP-HR-PORTAL-01",
                name="workday-hr-integration-service",
                business_unit="Corporate IT",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=20_000.0,
                downtime_cost_per_hour=10_000.0,
                dependent_services=[],
                hostname="hr.internal.apexglobal.net",
                ip_address="10.10.3.30",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CORP-EXCHANGE-MAIL-01",
                name="microsoft-exchange-hybrid-mail-relay",
                business_unit="Corporate IT",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=25_000.0,
                downtime_cost_per_hour=15_000.0,
                dependent_services=[],
                hostname="mail-relay-01.corp.apexglobal.net",
                ip_address="10.10.3.40",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CORP-VPN-GW-01",
                name="cisco-anyconnect-vpn-concentrator",
                business_unit="Corporate IT",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.API_GATEWAY,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=30_000.0,
                downtime_cost_per_hour=20_000.0,
                dependent_services=[],
                hostname="vpn.apexglobal.com",
                ip_address="198.51.100.50",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CORP-WORKSTATION-01",
                name="cfo-executive-laptop-windows11",
                business_unit="Corporate IT",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.ENDPOINT,
                data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
                replacement_cost=3_500.0,
                downtime_cost_per_hour=2_000.0,
                dependent_services=[],
                hostname="cfo-nb-01.corp.apexglobal.net",
                ip_address="10.20.3.15",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CORP-WORKSTATION-02",
                name="secops-analyst-workstation-ubuntu",
                business_unit="Corporate IT",
                environment=EnvironmentTier.PRODUCTION,
                asset_type=AssetType.ENDPOINT,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=3_000.0,
                downtime_cost_per_hour=1_000.0,
                dependent_services=[],
                hostname="sec-ws-01.corp.apexglobal.net",
                ip_address="10.20.3.25",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CORP-STG-ERP-01",
                name="sap-s4hana-staging-qa-sandbox",
                business_unit="Corporate IT",
                environment=EnvironmentTier.STAGING,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.INTERNAL,
                replacement_cost=15_000.0,
                downtime_cost_per_hour=500.0,
                dependent_services=[],
                hostname="erp-qa-01.internal.apexglobal.net",
                ip_address="10.10.13.10",
            )
        )
        assets.append(
            AssetRecord(
                asset_id="CORP-DEV-SANDBOX-01",
                name="developer-test-sandbox-isolated",
                business_unit="Corporate IT",
                environment=EnvironmentTier.SANDBOX,
                asset_type=AssetType.SERVER,
                data_sensitivity_tier=DataSensitivityTier.PUBLIC,
                replacement_cost=1_000.0,
                downtime_cost_per_hour=0.0,
                dependent_services=[],
                hostname="dev-sandbox-01.test.apexglobal.net",
                ip_address="10.99.99.99",
            )
        )

        return assets

    def build_dependency_graph(
        self,
        services: Optional[List[BusinessService]] = None,
        assets: Optional[List[AssetRecord]] = None,
    ) -> EnterpriseDependencyGraph:
        """Constructs and populates the EnterpriseDependencyGraph with services, assets, and edges."""
        graph = EnterpriseDependencyGraph()
        svcs = services or self.generate_business_services()
        ast_list = assets or self.generate_assets()

        for s in svcs:
            graph.add_business_service(s)
        for a in ast_list:
            graph.add_asset(a)

        # Connect services to primary assets
        # SWIFT Wire Settlement -> HSM Cluster, Gateway, Payment DB
        graph.add_dependency("SVC-SWIFT-SETTLE", "PAY-SWIFT-GW-01")
        graph.add_dependency("PAY-SWIFT-GW-01", "PAY-HSM-CLUSTER-01")
        graph.add_dependency("PAY-SWIFT-GW-01", "PAY-DB-01")

        # Payment Gateway -> API Gateway, Clearing, Kafka, Redis, Payment DB
        graph.add_dependency("SVC-PAY-GATEWAY", "PAY-API-GW-01")
        graph.add_dependency("PAY-API-GW-01", "PAY-CLEARING-APP-01")
        graph.add_dependency("PAY-CLEARING-APP-01", "PAY-REDIS-CACHE-01")
        graph.add_dependency("PAY-CLEARING-APP-01", "PAY-KAFKA-BROKER-01")
        graph.add_dependency("PAY-CLEARING-APP-01", "PAY-DB-01")
        graph.add_dependency("PAY-CLEARING-APP-01", "PAY-DB-02")
        graph.add_dependency("PAY-CLEARING-APP-01", "PAY-S3-ARCHIVE-01")

        # Card Switch -> Card Auth containers, HSM, Kafka, Payment DB
        graph.add_dependency("SVC-CARD-SWITCH", "PAY-CARD-AUTH-01")
        graph.add_dependency("SVC-CARD-SWITCH", "PAY-CARD-AUTH-02")
        graph.add_dependency("PAY-CARD-AUTH-01", "PAY-HSM-CLUSTER-01")
        graph.add_dependency("PAY-CARD-AUTH-01", "PAY-DB-01")
        graph.add_dependency("PAY-CARD-AUTH-02", "PAY-HSM-CLUSTER-01")
        graph.add_dependency("PAY-CARD-AUTH-02", "PAY-DB-01")

        # Retail Mobile -> API Gateway, Mobile Backends, Auth Service, Customer DB, S3 KYC
        graph.add_dependency("SVC-RETAIL-MOBILE", "RET-API-GATEWAY-01")
        graph.add_dependency("RET-API-GATEWAY-01", "RET-APP-MOBILE-01")
        graph.add_dependency("RET-API-GATEWAY-01", "RET-APP-MOBILE-02")
        graph.add_dependency("RET-APP-MOBILE-01", "RET-AUTH-SERVICE-01")
        graph.add_dependency("RET-APP-MOBILE-01", "RET-DB-CUSTOMER-01")
        graph.add_dependency("RET-APP-MOBILE-01", "RET-S3-KYC-01")
        graph.add_dependency("RET-APP-MOBILE-02", "RET-DB-CUSTOMER-01")
        graph.add_dependency("SVC-RETAIL-MOBILE", "RET-ATM-GW-01")
        graph.add_dependency("RET-ATM-GW-01", "RET-DB-CUSTOMER-01")

        # Retail Portal -> Web frontend, Customer DB, S3 KYC
        graph.add_dependency("SVC-RETAIL-PORTAL", "RET-WEB-PORTAL-01")
        graph.add_dependency("RET-WEB-PORTAL-01", "RET-AUTH-SERVICE-01")
        graph.add_dependency("RET-WEB-PORTAL-01", "RET-DB-CUSTOMER-01")
        graph.add_dependency("RET-WEB-PORTAL-01", "RET-S3-KYC-01")

        # Wealth Advisory -> Portal, App, Portfolio DB, Statements
        graph.add_dependency("SVC-WEALTH-ADVISORY", "WLT-CLIENT-PORTAL-01")
        graph.add_dependency("WLT-CLIENT-PORTAL-01", "WLT-ADVISORY-APP-01")
        graph.add_dependency("WLT-ADVISORY-APP-01", "WLT-DB-PORTFOLIO-01")
        graph.add_dependency("WLT-ADVISORY-APP-01", "WLT-S3-STATEMENTS-01")

        # Algo Trading -> FIX API, Algo Engine, Market Data Feed, Portfolio DB
        graph.add_dependency("SVC-ALGO-TRADING", "WLT-API-GATEWAY-01")
        graph.add_dependency("WLT-API-GATEWAY-01", "WLT-ALGO-ENGINE-01")
        graph.add_dependency("WLT-ALGO-ENGINE-01", "WLT-MARKET-FEED-01")
        graph.add_dependency("WLT-ALGO-ENGINE-01", "WLT-DB-PORTFOLIO-01")

        # Cloud Fabric -> Ingress Proxies, K8s Master, Worker Nodes, IAM Vault
        graph.add_dependency("SVC-CLOUD-FABRIC", "CLOUD-INGRESS-PROXY-01")
        graph.add_dependency("SVC-CLOUD-FABRIC", "CLOUD-INGRESS-PROXY-02")
        graph.add_dependency("CLOUD-INGRESS-PROXY-01", "CLOUD-K8S-PROD-CP")
        graph.add_dependency("CLOUD-K8S-PROD-CP", "CLOUD-K8S-WORKER-01")
        graph.add_dependency("CLOUD-K8S-PROD-CP", "CLOUD-K8S-WORKER-02")
        graph.add_dependency("CLOUD-K8S-PROD-CP", "CLOUD-IAM-VAULT-01")

        # Cross-tier infrastructure dependencies
        graph.add_dependency("PAY-DB-01", "CLOUD-IAM-VAULT-01")
        graph.add_dependency("RET-DB-CUSTOMER-01", "CLOUD-IAM-VAULT-01")

        # Corporate ERP -> ERP App, ERP DB, Domain Controller
        graph.add_dependency("SVC-CORP-ERP", "CORP-ERP-APP-01")
        graph.add_dependency("CORP-ERP-APP-01", "CORP-ERP-DB-01")
        graph.add_dependency("CORP-ERP-APP-01", "CORP-AD-DC-01")

        return graph

    def populate_asset_criticality(
        self, assets: List[AssetRecord], graph: EnterpriseDependencyGraph
    ) -> List[AssetRecord]:
        """Calculates dynamic ACS and financial valuation for each asset in the graph."""
        centrality_metrics = graph.calculate_centrality()

        for a in assets:
            perc = graph.percolate_failure(a.asset_id)
            cent = centrality_metrics.get(a.asset_id, {})
            a.financial_asset_valuation = calculate_asset_financial_valuation(a, perc)
            a.asset_criticality_score = calculate_asset_criticality_score(a, perc, cent)

        return assets

    def generate_vulnerabilities(self, assets: List[AssetRecord]) -> List[VulnerabilityFinding]:
        """Generates realistic CVE vulnerability findings mapped across assets."""
        vulns: List[VulnerabilityFinding] = []
        now = datetime.now(timezone.utc)

        # 1. Critical Log4j vulnerability on Payment Gateway API
        vulns.append(
            VulnerabilityFinding(
                finding_id="VULN-2021-44228-PAY",
                asset_id="PAY-API-GW-01",
                cve_id="CVE-2021-44228",
                title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
                cvss_score=10.0,
                attack_vector="NETWORK",
                exploitability_subscore=3.9,
                impact_subscore=6.0,
                epss_score=0.975,
                epss_percentile=0.999,
                exploit_maturity=ExploitMaturity.WEAPONIZED,
                cisa_kev=True,
                patch_available=True,
                discovered_at=now - timedelta(days=5),
            )
        )

        # 2. Critical OpenSSL CVE on Core Payment DB
        vulns.append(
            VulnerabilityFinding(
                finding_id="VULN-2023-38606-PAYDB",
                asset_id="PAY-DB-01",
                cve_id="CVE-2023-38606",
                title="OpenSSL Buffer Overrun during X.509 Certificate Verification",
                cvss_score=9.8,
                attack_vector="NETWORK",
                exploitability_subscore=3.9,
                impact_subscore=5.9,
                epss_score=0.884,
                epss_percentile=0.985,
                exploit_maturity=ExploitMaturity.HIGH,
                cisa_kev=True,
                patch_available=True,
                discovered_at=now - timedelta(days=12),
            )
        )

        # 3. Identical CVE-2023-38606 placed on Developer Sandbox for impact comparison!
        vulns.append(
            VulnerabilityFinding(
                finding_id="VULN-2023-38606-SANDBOX",
                asset_id="CORP-DEV-SANDBOX-01",
                cve_id="CVE-2023-38606",
                title="OpenSSL Buffer Overrun during X.509 Certificate Verification (Sandbox Test)",
                cvss_score=9.8,
                attack_vector="NETWORK",
                exploitability_subscore=3.9,
                impact_subscore=5.9,
                epss_score=0.884,
                epss_percentile=0.985,
                exploit_maturity=ExploitMaturity.HIGH,
                cisa_kev=True,
                patch_available=True,
                discovered_at=now - timedelta(days=2),
            )
        )

        # 4. Spring4Shell on Retail Mobile Backend
        vulns.append(
            VulnerabilityFinding(
                finding_id="VULN-2022-22965-RET",
                asset_id="RET-APP-MOBILE-01",
                cve_id="CVE-2022-22965",
                title="Spring Framework Remote Code Execution via Data Binding (Spring4Shell)",
                cvss_score=9.8,
                attack_vector="NETWORK",
                exploitability_subscore=3.9,
                impact_subscore=5.9,
                epss_score=0.912,
                epss_percentile=0.992,
                exploit_maturity=ExploitMaturity.WEAPONIZED,
                cisa_kev=True,
                patch_available=True,
                discovered_at=now - timedelta(days=8),
            )
        )

        # 5. High OpenSSH CVE on Cloud Bastion Jump Host
        vulns.append(
            VulnerabilityFinding(
                finding_id="VULN-2024-6387-CLOUD",
                asset_id="CLOUD-BASTION-JUMP-01",
                cve_id="CVE-2024-6387",
                title="OpenSSH regreSSHion Signal Handler Race Condition Vulnerability",
                cvss_score=8.1,
                attack_vector="NETWORK",
                exploitability_subscore=2.2,
                impact_subscore=5.9,
                epss_score=0.450,
                epss_percentile=0.920,
                exploit_maturity=ExploitMaturity.PROOF_OF_CONCEPT,
                cisa_kev=False,
                patch_available=True,
                discovered_at=now - timedelta(days=14),
            )
        )

        # 6. Medium SQLite CVE on Wealth Advisory Portal
        vulns.append(
            VulnerabilityFinding(
                finding_id="VULN-2022-35737-WLT",
                asset_id="WLT-ADVISORY-APP-01",
                cve_id="CVE-2022-35737",
                title="SQLite Array-bounds Overflow in printf Function",
                cvss_score=6.5,
                attack_vector="LOCAL",
                exploitability_subscore=1.8,
                impact_subscore=4.2,
                epss_score=0.035,
                epss_percentile=0.680,
                exploit_maturity=ExploitMaturity.FUNCTIONAL,
                cisa_kev=False,
                patch_available=True,
                discovered_at=now - timedelta(days=20),
            )
        )

        # 7. Low Information Disclosure on Corporate HR Portal
        vulns.append(
            VulnerabilityFinding(
                finding_id="VULN-2023-28772-CORP",
                asset_id="CORP-HR-PORTAL-01",
                cve_id="CVE-2023-28772",
                title="Apache HTTP Server Information Disclosure via Trace/Track",
                cvss_score=3.7,
                attack_vector="NETWORK",
                exploitability_subscore=2.2,
                impact_subscore=1.4,
                epss_score=0.008,
                epss_percentile=0.350,
                exploit_maturity=ExploitMaturity.UNPROVEN,
                cisa_kev=False,
                patch_available=False,
                discovered_at=now - timedelta(days=30),
            )
        )

        return vulns

    def generate_siem_alerts(self, assets: List[AssetRecord]) -> List[SiemAlertFinding]:
        """Generates realistic SIEM alerts simulating multi-stage attack progressions."""
        alerts: List[SiemAlertFinding] = []
        now = datetime.now(timezone.utc)

        # 1. Active Exfiltration detection on Payment S3 Archive
        alerts.append(
            SiemAlertFinding(
                alert_id="SIEM-ALT-90412",
                asset_id="PAY-S3-ARCHIVE-01",
                rule_name="Unusual High-Volume Outbound Data Transfer to Unknown IP",
                alert_count=18,
                mitre_tactic="Exfiltration",
                mitre_technique="T1048",
                severity=SeverityLevel.CRITICAL,
                exfiltration=True,
                lateral_movement=False,
                brute_force=False,
                anomalous_login=False,
                confidence=0.92,
                timestamp=now - timedelta(hours=2),
            )
        )

        # 2. Lateral Movement on Payment Bastion Host
        alerts.append(
            SiemAlertFinding(
                alert_id="SIEM-ALT-90350",
                asset_id="PAY-ADMIN-JUMP-01",
                rule_name="Suspicious PsExec Lateral Movement Attempt via SMB",
                alert_count=8,
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.002",
                severity=SeverityLevel.HIGH,
                exfiltration=False,
                lateral_movement=True,
                brute_force=False,
                anomalous_login=False,
                confidence=0.88,
                timestamp=now - timedelta(hours=5),
            )
        )

        # 3. Brute Force / Password Spraying on Corporate Active Directory
        alerts.append(
            SiemAlertFinding(
                alert_id="SIEM-ALT-89912",
                asset_id="CORP-AD-DC-01",
                rule_name="Active Directory Kerberos Pre-Authentication Brute Force",
                alert_count=45,
                mitre_tactic="Credential Access",
                mitre_technique="T1110.003",
                severity=SeverityLevel.HIGH,
                exfiltration=False,
                lateral_movement=False,
                brute_force=True,
                anomalous_login=False,
                confidence=0.95,
                timestamp=now - timedelta(hours=10),
            )
        )

        # 4. Anomalous Geolocation Login on Wealth Trader Workstation
        alerts.append(
            SiemAlertFinding(
                alert_id="SIEM-ALT-88741",
                asset_id="WLT-TRADER-WS-01",
                rule_name="Impossible Travel: Login from Concurrent Geo-Locations",
                alert_count=2,
                mitre_tactic="Initial Access",
                mitre_technique="T1078",
                severity=SeverityLevel.MEDIUM,
                exfiltration=False,
                lateral_movement=False,
                brute_force=False,
                anomalous_login=True,
                confidence=0.75,
                timestamp=now - timedelta(days=1),
            )
        )

        # 5. Suspicious Process Execution on Cloud Bastion
        alerts.append(
            SiemAlertFinding(
                alert_id="SIEM-ALT-88102",
                asset_id="CLOUD-BASTION-JUMP-01",
                rule_name="Suspicious Base64 Encoded Command Line Invocation",
                alert_count=3,
                mitre_tactic="Execution",
                mitre_technique="T1059.001",
                severity=SeverityLevel.MEDIUM,
                exfiltration=False,
                lateral_movement=False,
                brute_force=False,
                anomalous_login=False,
                confidence=0.70,
                timestamp=now - timedelta(days=2),
            )
        )

        return alerts

    def generate_iam_findings(self, assets: List[AssetRecord]) -> List[IamFinding]:
        """Generates realistic IAM configuration findings reflecting privilege hygiene."""
        iam_findings: List[IamFinding] = []

        # 1. Admin without MFA on Cloud AWS Root Account (Critical)
        iam_findings.append(
            IamFinding(
                identity_id="IAM-AWS-ROOT-ADMIN",
                asset_id="CLOUD-AWS-ROOT-ACC",
                account_name="root-breakglass-admin",
                role="OrganizationAccountAccessRole",
                is_admin=True,
                mfa_enabled=False,
                is_dormant=False,
                excess_privileges=True,
                inactive_days=15,
                high_risk_permissions=["*:*", "iam:PassRole", "kms:Decrypt"],
            )
        )

        # 2. Dormant Administrator on Payment Database
        iam_findings.append(
            IamFinding(
                identity_id="IAM-PAY-DBA-DORMANT",
                asset_id="PAY-DB-01",
                account_name="oracle_sys_contractor",
                role="DBA_SUPERUSER",
                is_admin=True,
                mfa_enabled=True,
                is_dormant=True,
                excess_privileges=True,
                inactive_days=120,
                high_risk_permissions=["ALTER SYSTEM", "DROP ANY TABLE"],
            )
        )

        # 3. Excess Permissions on Retail Auth Service Account
        iam_findings.append(
            IamFinding(
                identity_id="IAM-RET-SVC-EXCESS",
                asset_id="RET-AUTH-SERVICE-01",
                account_name="svc-retail-auth-connector",
                role="AppRole-RetailAuth",
                is_admin=False,
                mfa_enabled=True,
                is_dormant=False,
                excess_privileges=True,
                inactive_days=0,
                high_risk_permissions=["s3:GetObject", "s3:PutObject"],
            )
        )

        # 4. Standard Developer Account on Sandbox (Low Risk)
        iam_findings.append(
            IamFinding(
                identity_id="IAM-CORP-DEV-USER",
                asset_id="CORP-DEV-SANDBOX-01",
                account_name="dev-jdoe-test",
                role="SandboxTesterRole",
                is_admin=False,
                mfa_enabled=True,
                is_dormant=False,
                excess_privileges=False,
                inactive_days=1,
                high_risk_permissions=[],
            )
        )

        return iam_findings

    def generate_edr_telemetry(self, assets: List[AssetRecord]) -> List[EdrTelemetryFinding]:
        """Generates realistic EDR sensor telemetry."""
        edr_list: List[EdrTelemetryFinding] = []

        # 1. Process Injection on Corporate Executive Laptop
        edr_list.append(
            EdrTelemetryFinding(
                agent_id="EDR-AGT-0012",
                asset_id="CORP-WORKSTATION-01",
                endpoint_hostname="cfo-nb-01.corp.apexglobal.net",
                agent_status=EdrStatus.HEALTHY,
                definition_version="2026.09.01",
                days_since_update=6,
                tamper_protection=True,
                active_threats_count=1,
                suspicious_process_injection=True,
                endpoint_isolated=False,
            )
        )

        # 2. Degraded EDR sensor on Wealth Algo Engine
        edr_list.append(
            EdrTelemetryFinding(
                agent_id="EDR-AGT-0045",
                asset_id="WLT-ALGO-ENGINE-01",
                endpoint_hostname="algo-srv-01.internal.apexglobal.net",
                agent_status=EdrStatus.DEGRADED,
                definition_version="2026.07.15",
                days_since_update=52,
                tamper_protection=False,
                active_threats_count=0,
                suspicious_process_injection=False,
                endpoint_isolated=False,
            )
        )

        # 3. Healthy Agent on Core Payment DB
        edr_list.append(
            EdrTelemetryFinding(
                agent_id="EDR-AGT-0088",
                asset_id="PAY-DB-01",
                endpoint_hostname="db-pay-cluster01.internal.apexglobal.net",
                agent_status=EdrStatus.HEALTHY,
                definition_version="2026.09.07",
                days_since_update=1,
                tamper_protection=True,
                active_threats_count=0,
                suspicious_process_injection=False,
                endpoint_isolated=False,
            )
        )

        # 4. Stopped EDR on Developer Test Sandbox
        edr_list.append(
            EdrTelemetryFinding(
                agent_id="EDR-AGT-0099",
                asset_id="CORP-DEV-SANDBOX-01",
                endpoint_hostname="dev-sandbox-01.test.apexglobal.net",
                agent_status=EdrStatus.STOPPED,
                definition_version="2025.12.01",
                days_since_update=280,
                tamper_protection=False,
                active_threats_count=0,
                suspicious_process_injection=False,
                endpoint_isolated=False,
            )
        )

        return edr_list

    def generate_cspm_findings(self, assets: List[AssetRecord]) -> List[CspmFinding]:
        """Generates realistic CSPM cloud misconfiguration findings."""
        cspm_list: List[CspmFinding] = []

        # 1. Public Exposure + Unencrypted PII on Retail KYC S3 Bucket (Critical)
        cspm_list.append(
            CspmFinding(
                resource_id="arn:aws:s3:::apex-retail-customer-kyc-documents",
                asset_id="RET-S3-KYC-01",
                cloud_provider=CloudProvider.AWS,
                service="S3",
                public_exposure=True,
                open_ports=[443],
                unencrypted_data=True,
                missing_backup=False,
                compliance_drift_count=4,
                severity=SeverityLevel.CRITICAL,
            )
        )

        # 2. Open Sensitive SSH Port (0.0.0.0/0:22) on Cloud Bastion
        cspm_list.append(
            CspmFinding(
                resource_id="sg-0192a8b7c3d4e5f60-bastion",
                asset_id="CLOUD-BASTION-JUMP-01",
                cloud_provider=CloudProvider.AWS,
                service="SecurityGroup",
                public_exposure=True,
                open_ports=[22],
                unencrypted_data=False,
                missing_backup=False,
                compliance_drift_count=2,
                severity=SeverityLevel.HIGH,
            )
        )

        # 3. Missing Backup on Wealth Portfolio DB
        cspm_list.append(
            CspmFinding(
                resource_id="rds-pg-wlt-cluster-01",
                asset_id="WLT-DB-PORTFOLIO-01",
                cloud_provider=CloudProvider.AWS,
                service="RDS",
                public_exposure=False,
                open_ports=[],
                unencrypted_data=False,
                missing_backup=True,
                compliance_drift_count=1,
                severity=SeverityLevel.MEDIUM,
            )
        )

        # 4. Sandbox Cloud Bucket Misconfiguration (Low Risk)
        cspm_list.append(
            CspmFinding(
                resource_id="arn:aws:s3:::apex-dev-sandbox-public-test",
                asset_id="CORP-DEV-SANDBOX-01",
                cloud_provider=CloudProvider.AWS,
                service="S3",
                public_exposure=True,
                open_ports=[],
                unencrypted_data=True,
                missing_backup=True,
                compliance_drift_count=3,
                severity=SeverityLevel.LOW,
            )
        )

        return cspm_list

    def generate_all_telemetry(
        self, assets: Optional[List[AssetRecord]] = None
    ) -> Dict[str, List[Any]]:
        """Generates all raw telemetry across the 5 domains."""
        ast = assets or self.generate_assets()
        return {
            "vulnerabilities": self.generate_vulnerabilities(ast),
            "siem_alerts": self.generate_siem_alerts(ast),
            "iam_findings": self.generate_iam_findings(ast),
            "edr_telemetry": self.generate_edr_telemetry(ast),
            "cspm_findings": self.generate_cspm_findings(ast),
        }

    def generate_enterprise_dataset(
        self,
    ) -> Tuple[List[AssetRecord], List[NormalizedFinding], EnterpriseDependencyGraph]:
        """
        Main entrypoint: Generates the full ApexGlobal Financial Corp dataset:
          1. 65 Assets across 5 Business Units
          2. Dependency DAG with percolation and calculated ACS scores
          3. Unified NormalizedFindings across all 5 telemetry domains
        """
        services = self.generate_business_services()
        assets = self.generate_assets()
        graph = self.build_dependency_graph(services, assets)
        assets = self.populate_asset_criticality(assets, graph)

        raw_telemetry = self.generate_all_telemetry(assets)
        normalized_findings: List[NormalizedFinding] = []

        for v in raw_telemetry["vulnerabilities"]:
            normalized_findings.append(TelemetryNormalizer.normalize_vulnerability(v))
        for s in raw_telemetry["siem_alerts"]:
            normalized_findings.append(TelemetryNormalizer.normalize_siem(s))
        for i in raw_telemetry["iam_findings"]:
            normalized_findings.append(TelemetryNormalizer.normalize_iam(i))
        for e in raw_telemetry["edr_telemetry"]:
            normalized_findings.append(TelemetryNormalizer.normalize_edr(e))
        for c in raw_telemetry["cspm_findings"]:
            normalized_findings.append(TelemetryNormalizer.normalize_cspm(c))

        return assets, normalized_findings, graph
