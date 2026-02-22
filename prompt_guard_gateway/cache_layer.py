"""Response caching layer for performance optimization"""

import hashlib
import json
import time
from typing import Optional
from datetime import datetime, timedelta

class ResponseCache:
    """In-memory cache with TTL support"""
    
    def __init__(self, ttl_seconds: int = 300, max_size: int = 10000):
        self.cache = {}
        self.ttl = ttl_seconds
        self.max_size = max_size
        self.hits = 0
        self.misses = 0
    
    def _get_key(self, text: str, session_id: str) -> str:
        """Generate cache key from text and session"""
        return hashlib.sha256(f"{text}:{session_id}".encode()).hexdigest()
    
    def get(self, text: str, session_id: str) -> Optional[dict]:
        """Get cached response if exists and not expired"""
        key = self._get_key(text, session_id)
        
        if key in self.cache:
            entry, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                self.hits += 1
                return entry
            del self.cache[key]
        
        self.misses += 1
        return None
    
    def set(self, text: str, session_id: str, result: dict):
        """Cache response with current timestamp"""
        if len(self.cache) >= self.max_size:
            oldest = min(self.cache.items(), key=lambda x: x[1][1])
            del self.cache[oldest[0]]
        
        key = self._get_key(text, session_id)
        self.cache[key] = (result, time.time())
    
    def clear(self):
        """Clear all cached entries"""
        self.cache.clear()
        self.hits = 0
        self.misses = 0
    
    def stats(self) -> dict:
        """Get cache statistics"""
        total = self.hits + self.misses
        hit_rate = self.hits / total if total > 0 else 0
        
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(hit_rate, 3),
            "ttl_seconds": self.ttl
        }

# Global cache instance
_cache = None

def get_cache() -> ResponseCache:
    """Get or create global cache instance"""
    global _cache
    if _cache is None:
        _cache = ResponseCache()
    return _cache
