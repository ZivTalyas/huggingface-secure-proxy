#!/usr/bin/env python3
"""
Redis Caching Demo for Safe Input Proxy

This script demonstrates the performance benefits of Redis caching
by sending multiple validation requests and showing cache hit/miss statistics.
"""

import requests
import time
import json
import sys
from typing import Dict, Any, List

# Configuration
BACKEND_URL = "http://localhost:8001"  # Adjust if needed
TEST_TEXTS = [
    "Hello world, this is a safe message",
    "This is another safe text input",
    "Please process this innocent request",
    "'; DROP TABLE users; --",  # SQL injection attempt
    "<script>alert('XSS')</script>",  # XSS attempt
    "Hello world, this is a safe message",  # Duplicate for cache hit
    "This is another safe text input",  # Duplicate for cache hit
]

def make_validation_request(text: str) -> Dict[str, Any]:
    """Make a validation request to the backend."""
    try:
        response = requests.post(
            f"{BACKEND_URL}/validate",
            json={"text": text},
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return {}
            
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return {}

def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics from the backend."""
    try:
        response = requests.get(f"{BACKEND_URL}/cache/stats", timeout=10)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error getting cache stats: {response.status_code}")
            return {}
            
    except requests.exceptions.RequestException as e:
        print(f"Failed to get cache stats: {e}")
        return {}

def clear_cache() -> bool:
    """Clear the cache."""
    try:
        response = requests.post(f"{BACKEND_URL}/cache/clear", timeout=10)
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"Failed to clear cache: {e}")
        return False

def run_performance_test():
    """Run performance test showing cache benefits."""
    print("🚀 Redis Caching Performance Demo")
    print("=" * 50)
    
    # Clear cache first
    print("\n1. Clearing cache...")
    if clear_cache():
        print("   ✅ Cache cleared successfully")
    else:
        print("   ❌ Failed to clear cache")
    
    # Get initial stats
    initial_stats = get_cache_stats()
    print(f"\n2. Initial cache stats:")
    if initial_stats:
        cache_perf = initial_stats.get("cache_performance", {})
        print(f"   - Cache hits: {cache_perf.get('total_hits', 0)}")
        print(f"   - Cache misses: {cache_perf.get('total_misses', 0)}")
        print(f"   - Hit rate: {cache_perf.get('hit_rate', 0):.1f}%")
    
    print(f"\n3. Testing validation with {len(TEST_TEXTS)} requests...")
    print("   (Some texts are duplicates to demonstrate cache hits)")
    
    # Track timing
    times = []
    results = []
    
    for i, text in enumerate(TEST_TEXTS, 1):
        print(f"\n   Request {i}: '{text[:50]}{'...' if len(text) > 50 else ''}'")
        
        start_time = time.time()
        result = make_validation_request(text)
        end_time = time.time()
        
        request_time = (end_time - start_time) * 1000  # Convert to ms
        times.append(request_time)
        results.append(result)
        
        if result:
            cache_hit = result.get("cache_hit", False)
            processing_time = result.get("processing_time_ms", 0)
            status = result.get("status", "unknown")
            
            print(f"     - Status: {status}")
            print(f"     - Cache hit: {'✅' if cache_hit else '❌'}")
            print(f"     - Processing time: {processing_time:.1f}ms")
            print(f"     - Total request time: {request_time:.1f}ms")
        else:
            print(f"     - Request failed")
    
    # Get final stats
    final_stats = get_cache_stats()
    
    print(f"\n4. Final results:")
    print(f"   - Total requests: {len(TEST_TEXTS)}")
    print(f"   - Average request time: {sum(times) / len(times):.1f}ms")
    print(f"   - Fastest request: {min(times):.1f}ms")
    print(f"   - Slowest request: {max(times):.1f}ms")
    
    if final_stats:
        cache_perf = final_stats.get("cache_performance", {})
        print(f"\n   Cache Performance:")
        print(f"   - Total hits: {cache_perf.get('total_hits', 0)}")
        print(f"   - Total misses: {cache_perf.get('total_misses', 0)}")
        print(f"   - Hit rate: {cache_perf.get('hit_rate', 0):.1f}%")
        
        # Show Redis info
        redis_info = final_stats.get("redis_info", {})
        if redis_info.get("connected"):
            print(f"\n   Redis Info:")
            print(f"   - Connected: ✅")
            print(f"   - Version: {redis_info.get('redis_version', 'unknown')}")
            print(f"   - Memory used: {redis_info.get('used_memory', 'unknown')}")
            print(f"   - Cache keys: {redis_info.get('validation_cache_keys', 0)}")
        else:
            print(f"\n   Redis Info: ❌ Not connected")

def analyze_cache_hits(results, times):
    """Analyze which requests were cache hits vs misses."""
    print("\n5. Cache Hit Analysis:")
    
    cache_hits = []
    cache_misses = []
    
    for i, result in enumerate(results, 1):
        if result:
            if result.get("cache_hit", False):
                cache_hits.append(i)
            else:
                cache_misses.append(i)
    
    print(f"   - Cache hits: {cache_hits}")
    print(f"   - Cache misses: {cache_misses}")
    
    # Show performance difference
    if cache_hits and cache_misses:
        hit_times = [times[i-1] for i in cache_hits]
        miss_times = [times[i-1] for i in cache_misses]
        
        avg_hit_time = sum(hit_times) / len(hit_times)
        avg_miss_time = sum(miss_times) / len(miss_times)
        
        print(f"\n   Performance difference:")
        print(f"   - Average cache hit time: {avg_hit_time:.1f}ms")
        print(f"   - Average cache miss time: {avg_miss_time:.1f}ms")
        print(f"   - Speed improvement: {((avg_miss_time - avg_hit_time) / avg_miss_time * 100):.1f}%")

def main():
    """Main function."""
    print("Checking backend connection...")
    
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=5)
        if response.status_code != 200:
            print(f"❌ Backend not healthy: {response.status_code}")
            sys.exit(1)
        
        health_data = response.json()
        redis_connected = health_data.get("redis", {}).get("connected", False)
        
        print(f"✅ Backend is healthy")
        print(f"   Redis connected: {'✅' if redis_connected else '❌'}")
        
        if not redis_connected:
            print("   ⚠️  Redis not connected - caching will be disabled")
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Cannot connect to backend: {e}")
        print(f"   Make sure the backend is running at {BACKEND_URL}")
        sys.exit(1)
    
    # Run the performance test
    run_performance_test()
    
    print("\n" + "=" * 50)
    print("🎯 Demo completed!")
    print("\nKey takeaways:")
    print("1. Cache hits are significantly faster than cache misses")
    print("2. Redis caching reduces response times for repeated requests")
    print("3. Cache hit rate improves as more requests are made")
    print("4. The system gracefully handles Redis unavailability")

if __name__ == "__main__":
    main() 