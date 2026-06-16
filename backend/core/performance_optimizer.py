"""
PERFORMANCE OPTIMIZER
Optimizes performance across HTTP, browser, and learning operations.

This optimizer:
1. Identifies bottlenecks across all system components
2. Optimizes resource allocation based on performance metrics
3. Balances learning overhead against scan performance
4. Recommends HTTP alternatives when browser is slow
5. Tracks end-to-end performance
6. Adapts operation mix to maximize throughput
"""

import logging
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict, deque

logger = logging.getLogger("PerformanceOptimizer")


@dataclass
class PerformanceMetrics:
    """Performance metrics for a component"""
    component: str
    avg_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    throughput_per_sec: float
    error_rate: float
    timestamp: float


class PerformanceOptimizer:
    """
    Optimizes performance across all system components.
    """
    
    def __init__(self):
        # Performance metrics by component
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Bottleneck tracking
        self.bottlenecks: List[Dict[str, Any]] = []
        
        # Operation mix tracking
        self.operation_counts = {
            "http": 0,
            "browser": 0,
            "learning": 0
        }
        
        # Performance thresholds
        self.thresholds = {
            "slow_response_ms": 2000,
            "high_error_rate": 0.1,
            "low_throughput": 1.0
        }
    
    def record_performance(
        self,
        component: str,
        response_time_ms: float,
        success: bool
    ):
        """Record performance metric for a component."""
        self.metrics[component].append({
            "response_time_ms": response_time_ms,
            "success": success,
            "timestamp": time.time()
        })
    
    def identify_bottlenecks(self) -> List[Dict[str, Any]]:
        """
        Identify performance bottlenecks across all components.
        Returns list of bottlenecks with recommendations.
        """
        bottlenecks = []
        
        for component, metrics_list in self.metrics.items():
            if not metrics_list:
                continue
            
            # Calculate statistics
            response_times = [m["response_time_ms"] for m in metrics_list]
            avg_response = sum(response_times) / len(response_times)
            
            # Sort for percentiles
            sorted_times = sorted(response_times)
            p95_index = int(len(sorted_times) * 0.95)
            p99_index = int(len(sorted_times) * 0.99)
            
            p95_response = sorted_times[p95_index] if p95_index < len(sorted_times) else sorted_times[-1]
            p99_response = sorted_times[p99_index] if p99_index < len(sorted_times) else sorted_times[-1]
            
            # Calculate error rate
            errors = sum(1 for m in metrics_list if not m["success"])
            error_rate = errors / len(metrics_list)
            
            # Calculate throughput
            time_span = metrics_list[-1]["timestamp"] - metrics_list[0]["timestamp"]
            throughput = len(metrics_list) / time_span if time_span > 0 else 0
            
            # Check for bottlenecks
            if p99_response > self.thresholds["slow_response_ms"]:
                bottlenecks.append({
                    "component": component,
                    "issue": "slow_response",
                    "p99_response_ms": p99_response,
                    "recommendation": self._get_slow_response_recommendation(component)
                })
            
            if error_rate > self.thresholds["high_error_rate"]:
                bottlenecks.append({
                    "component": component,
                    "issue": "high_error_rate",
                    "error_rate": error_rate,
                    "recommendation": self._get_error_rate_recommendation(component)
                })
            
            if throughput < self.thresholds["low_throughput"]:
                bottlenecks.append({
                    "component": component,
                    "issue": "low_throughput",
                    "throughput": throughput,
                    "recommendation": self._get_throughput_recommendation(component)
                })
        
        self.bottlenecks = bottlenecks
        
        if bottlenecks:
            logger.warning(f"[PerfOptimizer] Identified {len(bottlenecks)} bottlenecks")
        
        return bottlenecks
    
    def _get_slow_response_recommendation(self, component: str) -> str:
        """Get recommendation for slow response times."""
        if "browser" in component.lower():
            return "Consider using HTTP-only methods or PinchTab for simple operations"
        elif "learning" in component.lower():
            return "Reduce learning frequency or batch learning operations"
        else:
            return "Increase concurrency or optimize query performance"
    
    def _get_error_rate_recommendation(self, component: str) -> str:
        """Get recommendation for high error rates."""
        return "Enable circuit breakers and implement retry logic with exponential backoff"
    
    def _get_throughput_recommendation(self, component: str) -> str:
        """Get recommendation for low throughput."""
        return "Increase parallelism or optimize resource allocation"
    
    def balance_learning_overhead(
        self,
        scan_performance_ms: float,
        learning_overhead_ms: float
    ) -> Dict[str, Any]:
        """
        Balance learning overhead against scan performance.
        Returns recommendation for learning frequency.
        """
        overhead_percentage = (learning_overhead_ms / scan_performance_ms) * 100 if scan_performance_ms > 0 else 0
        
        recommendation = {
            "overhead_percentage": overhead_percentage,
            "acceptable": overhead_percentage < 5.0,
            "action": "none"
        }
        
        if overhead_percentage > 10.0:
            recommendation["action"] = "reduce_learning_frequency"
            recommendation["suggested_frequency"] = "every_10_scans"
        elif overhead_percentage > 5.0:
            recommendation["action"] = "batch_learning"
            recommendation["suggested_batch_size"] = 10
        
        logger.info(f"[PerfOptimizer] Learning overhead: {overhead_percentage:.1f}%")
        
        return recommendation
    
    def recommend_http_alternative(
        self,
        browser_performance_ms: float,
        http_performance_ms: float
    ) -> Dict[str, Any]:
        """
        Recommend HTTP alternative when browser operations are slow.
        """
        if http_performance_ms == 0:
            return {"recommend_http": False, "reason": "no_http_data"}
        
        speedup_factor = browser_performance_ms / http_performance_ms
        
        recommendation = {
            "recommend_http": speedup_factor > 3.0,
            "speedup_factor": speedup_factor,
            "browser_ms": browser_performance_ms,
            "http_ms": http_performance_ms
        }
        
        if recommendation["recommend_http"]:
            logger.info(f"[PerfOptimizer] Recommending HTTP ({speedup_factor:.1f}x faster)")
        
        return recommendation
    
    def adapt_operation_mix(
        self,
        target_throughput: float
    ) -> Dict[str, float]:
        """
        Adapt operation mix (HTTP vs browser) to maximize throughput.
        Returns recommended operation percentages.
        """
        # Get current performance for each operation type
        http_metrics = list(self.metrics.get("http", []))
        browser_metrics = list(self.metrics.get("browser", []))
        
        if not http_metrics or not browser_metrics:
            return {"http": 0.7, "browser": 0.3}  # Default mix
        
        # Calculate average response times
        http_avg = sum(m["response_time_ms"] for m in http_metrics) / len(http_metrics)
        browser_avg = sum(m["response_time_ms"] for m in browser_metrics) / len(browser_metrics)
        
        # Calculate throughput for each
        http_throughput = 1000 / http_avg if http_avg > 0 else 0  # ops per second
        browser_throughput = 1000 / browser_avg if browser_avg > 0 else 0
        
        # Optimize mix based on throughput
        if http_throughput > browser_throughput * 2:
            # HTTP is much faster, prefer it
            mix = {"http": 0.8, "browser": 0.2}
        elif browser_throughput > http_throughput * 2:
            # Browser is faster (unlikely but possible), prefer it
            mix = {"http": 0.3, "browser": 0.7}
        else:
            # Similar performance, balanced mix
            mix = {"http": 0.6, "browser": 0.4}
        
        logger.info(f"[PerfOptimizer] Recommended mix: HTTP {mix['http']:.0%}, Browser {mix['browser']:.0%}")
        
        return mix
    
    def track_end_to_end_performance(
        self,
        scan_id: str,
        total_time_ms: float,
        breakdown: Dict[str, float]
    ):
        """Track end-to-end performance including all components."""
        self.metrics["end_to_end"].append({
            "scan_id": scan_id,
            "total_time_ms": total_time_ms,
            "breakdown": breakdown,
            "timestamp": time.time()
        })
        
        # Log if performance is degrading
        if len(self.metrics["end_to_end"]) > 10:
            recent = list(self.metrics["end_to_end"])[-10:]
            avg_recent = sum(m["total_time_ms"] for m in recent) / len(recent)
            
            if total_time_ms > avg_recent * 1.5:
                logger.warning(f"[PerfOptimizer] Performance degradation detected: {total_time_ms:.0f}ms vs {avg_recent:.0f}ms avg")
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report."""
        report = {
            "bottlenecks": self.bottlenecks,
            "components": {},
            "operation_mix": self.operation_counts,
            "timestamp": time.time()
        }
        
        for component, metrics_list in self.metrics.items():
            if not metrics_list:
                continue
            
            response_times = [m["response_time_ms"] for m in metrics_list]
            avg_response = sum(response_times) / len(response_times)
            
            errors = sum(1 for m in metrics_list if not m["success"])
            error_rate = errors / len(metrics_list)
            
            report["components"][component] = {
                "avg_response_ms": round(avg_response, 2),
                "error_rate": round(error_rate, 3),
                "sample_size": len(metrics_list)
            }
        
        return report


# Global performance optimizer instance
performance_optimizer = PerformanceOptimizer()
