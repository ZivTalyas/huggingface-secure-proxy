"""
Redis service for caching validation results and improving performance.
"""
import json
import logging
import hashlib
import os
from typing import Dict, Any, Optional, Union
from datetime import timedelta
import redis
from redis.exceptions import ConnectionError, TimeoutError

logger = logging.getLogger(__name__)

class RedisService:
    """Service for Redis operations including caching validation results."""
    
    def __init__(self, host: str = None, port: int = None, db: int = 0):
        """Initialize Redis connection."""
        self.host = host or os.getenv("REDIS_HOST", "localhost")
        self.port = port or int(os.getenv("REDIS_PORT", "6379"))
        self.db = db
        
        # Cache settings
        self.default_ttl = int(os.getenv("REDIS_DEFAULT_TTL", "3600"))  # 1 hour
        self.text_cache_ttl = int(os.getenv("REDIS_TEXT_CACHE_TTL", "1800"))  # 30 minutes
        self.file_cache_ttl = int(os.getenv("REDIS_FILE_CACHE_TTL", "7200"))  # 2 hours
        
        # Initialize connection
        self.redis_client = None
        self.connected = False
        self._connect()
    
    def _connect(self):
        """Establish Redis connection."""
        try:
            self.redis_client = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
                health_check_interval=30
            )
            
            # Test the connection
            self.redis_client.ping()
            self.connected = True
            logger.info(f"Successfully connected to Redis at {self.host}:{self.port}")
            
        except (ConnectionError, TimeoutError) as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.connected = False
            self.redis_client = None
    
    def is_connected(self) -> bool:
        """Check if Redis connection is active."""
        if not self.connected or not self.redis_client:
            return False
        
        try:
            self.redis_client.ping()
            return True
        except Exception:
            self.connected = False
            return False
    
    def _ensure_connection(self):
        """Ensure Redis connection is active, reconnect if needed."""
        if not self.is_connected():
            logger.info("Reconnecting to Redis...")
            self._connect()
    
    def _generate_cache_key(self, content: str, analysis_type: str, security_level: str) -> str:
        """Generate a consistent cache key for content."""
        # Create hash of content + analysis parameters
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        return f"validation:{analysis_type}:{security_level}:{content_hash}"
    
    def cache_validation_result(self, content: str, analysis_type: str, 
                              security_level: str, result: Dict[str, Any], 
                              ttl: Optional[int] = None) -> bool:
        """Cache a validation result."""
        if not self.is_connected():
            return False
        
        try:
            self._ensure_connection()
            if not self.is_connected():
                return False
            
            cache_key = self._generate_cache_key(content, analysis_type, security_level)
            
            # Choose appropriate TTL based on analysis type
            if ttl is None:
                ttl = self.text_cache_ttl if analysis_type == "text" else self.file_cache_ttl
            
            # Add timestamp to result
            result_with_metadata = {
                **result,
                "cached_at": self.redis_client.time()[0],  # Redis timestamp
                "analysis_type": analysis_type,
                "security_level": security_level
            }
            
            # Store in Redis
            self.redis_client.setex(
                cache_key,
                ttl,
                json.dumps(result_with_metadata)
            )
            
            logger.debug(f"Cached validation result for {analysis_type} analysis (TTL: {ttl}s)")
            return True
            
        except Exception as e:
            logger.error(f"Error caching validation result: {e}")
            return False
    
    def get_cached_validation_result(self, content: str, analysis_type: str, 
                                   security_level: str) -> Optional[Dict[str, Any]]:
        """Retrieve a cached validation result."""
        if not self.is_connected():
            return None
        
        try:
            self._ensure_connection()
            if not self.is_connected():
                return None
            
            cache_key = self._generate_cache_key(content, analysis_type, security_level)
            
            # Get from Redis
            cached_result = self.redis_client.get(cache_key)
            if cached_result:
                result = json.loads(cached_result)
                logger.debug(f"Retrieved cached validation result for {analysis_type} analysis")
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving cached validation result: {e}")
            return None
    
    def cache_analysis_stats(self, stats: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Cache analysis statistics."""
        if not self.is_connected():
            return False
        
        try:
            self._ensure_connection()
            if not self.is_connected():
                return False
            
            ttl = ttl or self.default_ttl
            
            self.redis_client.setex(
                "analysis_stats",
                ttl,
                json.dumps(stats)
            )
            
            logger.debug("Cached analysis statistics")
            return True
            
        except Exception as e:
            logger.error(f"Error caching analysis stats: {e}")
            return False
    
    def get_analysis_stats(self) -> Optional[Dict[str, Any]]:
        """Get cached analysis statistics."""
        if not self.is_connected():
            return None
        
        try:
            self._ensure_connection()
            if not self.is_connected():
                return None
            
            cached_stats = self.redis_client.get("analysis_stats")
            if cached_stats:
                return json.loads(cached_stats)
            
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving analysis stats: {e}")
            return None
    
    def increment_counter(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment a counter in Redis."""
        if not self.is_connected():
            return None
        
        try:
            self._ensure_connection()
            if not self.is_connected():
                return None
            
            counter_key = f"counter:{key}"
            new_value = self.redis_client.incr(counter_key, amount)
            
            # Set TTL for counter (daily reset)
            self.redis_client.expire(counter_key, 86400)  # 24 hours
            
            return new_value
            
        except Exception as e:
            logger.error(f"Error incrementing counter {key}: {e}")
            return None
    
    def get_counter(self, key: str) -> Optional[int]:
        """Get counter value."""
        if not self.is_connected():
            return None
        
        try:
            self._ensure_connection()
            if not self.is_connected():
                return None
            
            counter_key = f"counter:{key}"
            value = self.redis_client.get(counter_key)
            
            return int(value) if value else 0
            
        except Exception as e:
            logger.error(f"Error getting counter {key}: {e}")
            return None
    
    def clear_cache(self, pattern: str = None) -> bool:
        """Clear cache entries matching pattern."""
        if not self.is_connected():
            return False
        
        try:
            self._ensure_connection()
            if not self.is_connected():
                return False
            
            if pattern:
                keys = self.redis_client.keys(pattern)
                if keys:
                    self.redis_client.delete(*keys)
                    logger.info(f"Cleared {len(keys)} cache entries matching pattern: {pattern}")
            else:
                self.redis_client.flushdb()
                logger.info("Cleared all cache entries")
            
            return True
            
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            return False
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache information and statistics."""
        if not self.is_connected():
            return {"connected": False, "error": "Not connected to Redis"}
        
        try:
            self._ensure_connection()
            if not self.is_connected():
                return {"connected": False, "error": "Connection failed"}
            
            info = self.redis_client.info()
            
            # Get key counts by pattern
            validation_keys = len(self.redis_client.keys("validation:*"))
            counter_keys = len(self.redis_client.keys("counter:*"))
            
            return {
                "connected": True,
                "redis_version": info.get("redis_version", "unknown"),
                "used_memory": info.get("used_memory_human", "unknown"),
                "connected_clients": info.get("connected_clients", 0),
                "total_keys": info.get("db0", {}).get("keys", 0) if "db0" in info else 0,
                "validation_cache_keys": validation_keys,
                "counter_keys": counter_keys,
                "uptime_seconds": info.get("uptime_in_seconds", 0)
            }
            
        except Exception as e:
            logger.error(f"Error getting cache info: {e}")
            return {"connected": False, "error": str(e)}

# Global Redis service instance
redis_service = RedisService() 