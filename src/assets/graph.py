"""Enterprise business service dependency DAG and percolation engine using NetworkX."""

from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx
from pydantic import BaseModel, Field

from src.assets.models import AssetRecord, BusinessService


class PercolationResult(BaseModel):
    """Result of cascading failure percolation analysis for an asset."""
    asset_id: str
    impacted_services: List[BusinessService] = Field(default_factory=list)
    impacted_assets: List[str] = Field(default_factory=list)
    total_upstream_revenue_per_hour: float = Field(default=0.0, ge=0.0)
    max_service_criticality: float = Field(default=0.1, ge=0.0, le=1.0)
    service_reachability_ratio: float = Field(default=0.0, ge=0.0, le=1.0)


class EnterpriseDependencyGraph:
    """
    NetworkX Directed Acyclic Graph (DAG) modeling enterprise dependencies.
    Directed edge (A, B) denotes: A depends on B (A -> B).
    Therefore, failure of B propagates backwards along edges to all ancestors of B in G.
    """

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self.services: Dict[str, BusinessService] = {}
        self.assets: Dict[str, AssetRecord] = {}

    def add_business_service(self, service: BusinessService) -> None:
        """Adds a business service root node to the dependency graph."""
        self.services[service.service_id] = service
        self.graph.add_node(
            service.service_id,
            node_type="service",
            name=service.name,
            business_unit=service.business_unit,
            revenue_per_hour=service.revenue_per_hour_downtime,
            criticality=service.criticality,
        )

    def add_asset(self, asset: AssetRecord) -> None:
        """Adds a technical asset node to the dependency graph."""
        self.assets[asset.asset_id] = asset
        self.graph.add_node(
            asset.asset_id,
            node_type="asset",
            name=asset.name,
            business_unit=asset.business_unit,
            asset_type=asset.asset_type.value,
            downtime_cost_per_hour=asset.downtime_cost_per_hour,
        )

    def add_dependency(self, source_id: str, target_id: str, dependency_type: str = "DEPENDS_ON") -> None:
        """
        Registers a directed dependency: source_id DEPENDS ON target_id.
        (e.g., Service 'SVC-PAYMENTS' -> Asset 'DB-PAYMENT-LEDGER')
        """
        self.graph.add_edge(source_id, target_id, relation=dependency_type)
        if not nx.is_directed_acyclic_graph(self.graph):
            self.graph.remove_edge(source_id, target_id)
            raise ValueError(f"Adding dependency {source_id} -> {target_id} creates a cyclic dependency in the DAG.")

    def is_valid_dag(self) -> bool:
        """Validates that the dependency structure is strictly a DAG."""
        return nx.is_directed_acyclic_graph(self.graph)

    def topological_sort(self) -> List[str]:
        """Returns topological ordering of dependencies."""
        if not self.is_valid_dag():
            raise ValueError("Dependency graph contains cycles, cannot perform topological sort.")
        return list(nx.topological_sort(self.graph))

    def get_upstream_dependents(self, node_id: str) -> Set[str]:
        """
        Returns all nodes (services and assets) that directly or indirectly depend on node_id.
        Since edge is (dependent, provider), all ancestors of node_id depend on it.
        """
        if node_id not in self.graph:
            return set()
        return nx.ancestors(self.graph, node_id)

    def get_upstream_services(self, node_id: str) -> List[BusinessService]:
        """Returns all BusinessServices that depend on node_id."""
        ancestors = self.get_upstream_dependents(node_id)
        services: List[BusinessService] = []
        for a in ancestors:
            if a in self.services:
                services.append(self.services[a])
        return services

    def percolate_failure(self, node_id: str) -> PercolationResult:
        """
        Percolates the operational failure of an infrastructure node or asset upstream.
        Aggregates total dependent revenue at risk and identifies all impacted services.
        """
        if node_id not in self.graph:
            # If asset is not explicitly registered in graph, return baseline isolated result
            asset = self.assets.get(node_id)
            downtime_cost = asset.downtime_cost_per_hour if asset else 0.0
            return PercolationResult(
                asset_id=node_id,
                impacted_services=[],
                impacted_assets=[],
                total_upstream_revenue_per_hour=downtime_cost,
                max_service_criticality=0.1,
                service_reachability_ratio=0.0,
            )

        ancestors = self.get_upstream_dependents(node_id)
        impacted_services: List[BusinessService] = []
        impacted_assets: List[str] = []
        service_revenue: float = 0.0
        max_crit: float = 0.1

        for a in ancestors:
            if a in self.services:
                svc = self.services[a]
                impacted_services.append(svc)
                service_revenue += svc.revenue_per_hour_downtime
                if svc.criticality > max_crit:
                    max_crit = svc.criticality
            elif a in self.assets:
                impacted_assets.append(a)

        # Include direct asset downtime cost if present
        direct_asset_cost = 0.0
        if node_id in self.assets:
            direct_asset_cost = self.assets[node_id].downtime_cost_per_hour

        total_rev = round(service_revenue + direct_asset_cost, 2)
        total_services_count = max(1, len(self.services))
        reachability = round(len(impacted_services) / total_services_count, 4)

        return PercolationResult(
            asset_id=node_id,
            impacted_services=impacted_services,
            impacted_assets=impacted_assets,
            total_upstream_revenue_per_hour=total_rev,
            max_service_criticality=round(max_crit, 3),
            service_reachability_ratio=reachability,
        )

    def calculate_centrality(self) -> Dict[str, Dict[str, float]]:
        """
        Computes network centrality metrics:
        - Betweenness centrality (measures bridge / single point of failure role)
        - In-degree centrality (number of direct dependents)
        """
        if len(self.graph) == 0:
            return {}

        betweenness = nx.betweenness_centrality(self.graph)
        in_degree = nx.in_degree_centrality(self.graph)

        metrics: Dict[str, Dict[str, float]] = {}
        for node in self.graph.nodes:
            metrics[node] = {
                "betweenness_centrality": round(betweenness.get(node, 0.0), 5),
                "in_degree_centrality": round(in_degree.get(node, 0.0), 5),
            }
        return metrics

    def identify_spofs(self, min_impacted_services: int = 2) -> List[str]:
        """
        Identifies Single Points of Failure (SPOFs) where failure causes cascading
        outages to at least min_impacted_services business services.
        """
        spofs: List[str] = []
        for asset_id in self.assets:
            result = self.percolate_failure(asset_id)
            if len(result.impacted_services) >= min_impacted_services:
                spofs.append(asset_id)
        return spofs
