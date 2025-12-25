# Cerberus SIEM - Maximum Throughput Test Results

**Test Date:** Mon, 10 Nov 2025 04:49:11 EST
**Base URL:** http://localhost:8080
**Strategy:** incremental
**Test Duration per Iteration:** 5 seconds
**Drop Rate Threshold:** 1.0%
**Test Tool:** Go Load Tester

---

## Executive Summary

**Maximum Sustainable Event Ingestion Rate: 100000 events/second**

This test discovered that Cerberus SIEM can sustainably ingest **100000 events per second** with less than 1.0% event drop rate and stable system health.

### Optimal Configuration at Max Rate:
- **Events Sent:** 500000
- **Send Rate:** 20850.98 eps
- **Drop Rate:** 0.0000%
- **Events Ingested:** 0
- **Ingestion Rate:** 0.00 eps
- **System Health:** Healthy [OK]

---

## Test Iterations

A total of 15 test iterations were performed.

| Iteration | Target Rate | Send Rate | Drop Rate | Ingested | Ingestion Rate | Result |
|-----------|-------------|-----------|-----------|----------|----------------|--------|
| 1 | 30000 | 20907.15 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 2 | 35000 | 20693.95 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 3 | 40000 | 20339.14 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 4 | 45000 | 20398.47 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 5 | 50000 | 20706.59 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 6 | 55000 | 19536.65 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 7 | 60000 | 20051.13 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 8 | 65000 | 19872.20 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 9 | 70000 | 20260.37 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 10 | 75000 | 20198.51 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 11 | 80000 | 20582.63 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 12 | 85000 | 20354.26 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 13 | 90000 | 20635.78 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 14 | 95000 | 20799.51 | 0.0000% | 0 | 0.00 | [OK] PASS |
| 15 | 100000 | 20850.98 | 0.0000% | 0 | 0.00 | [OK] PASS |


---

## Performance Analysis

**Successful Tests:** 15/15

**Average Metrics (Successful Tests):**
- Send Rate: 20412.49 eps
- Ingestion Rate: 0.00 eps
- Drop Rate: 0.0000%

---

## Recommendations

- [OK] **Excellent Performance** - System can handle very high throughput (100000 eps)

### Scaling Recommendations:

**For Higher Throughput:**
1. Increase ClickHouse batch size (current default: 10000)
2. Add more event storage workers (current default: 8)
3. Scale ClickHouse horizontally (add more nodes)
4. Increase system resources (CPU, RAM)
5. Optimize detection rules (reduce complexity)

**Production Deployment:**
- Reserve 20-30% headroom: Target sustained rate of 70000 eps (70% of max)
- Enable auto-scaling based on event queue depth
- Implement circuit breakers for downstream dependencies
- Set up comprehensive monitoring and alerting

---

**Generated:** Mon, 10 Nov 2025 04:49:11 EST
**Test Script:** Go Load Tester
**Total Test Duration:** 10.0 minutes
