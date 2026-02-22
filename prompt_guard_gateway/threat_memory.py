"""Threat Intelligence Memory - Vector-based attack pattern learning"""

import os
import json
import time
import logging
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
import numpy as np

logger = logging.getLogger(__name__)

# Lazy imports for embeddings
_sentence_transformer = None
_faiss_index = None

def get_sentence_transformer():
    """Lazy load sentence transformer model."""
    global _sentence_transformer
    if _sentence_transformer is None:
        try:
            from sentence_transformers import SentenceTransformer
            _sentence_transformer = SentenceTransformer('all-MiniLM-L6-v2')  # 384-dim, fast
            logger.info("Loaded sentence transformer: all-MiniLM-L6-v2")
        except ImportError:
            logger.warning("sentence-transformers not installed. Threat memory disabled.")
            _sentence_transformer = False
    return _sentence_transformer if _sentence_transformer else None


@dataclass
class ThreatMatch:
    """Result of threat memory search."""
    matched_attack_id: Optional[str] = None
    similarity_score: float = 0.0
    historical_frequency: int = 0
    attack_type: str = "NONE"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class ThreatMemory:
    """Vector database of known malicious prompts with temporal decay."""
    
    def __init__(
        self,
        storage_path: str = "logs/threat_memory.json",
        similarity_threshold: float = 0.85,
        risk_boost: float = 0.3,
        decay_days: int = 90,
        max_threats: int = 10000
    ):
        self.storage_path = storage_path
        self.similarity_threshold = similarity_threshold
        self.risk_boost = risk_boost
        self.decay_days = decay_days
        self.max_threats = max_threats
        
        self.threats = []  # List of threat dicts
        self.embeddings = None  # numpy array of embeddings
        self.model = get_sentence_transformer()
        
        self._load()
    
    def _load(self):
        """Load threat database from disk."""
        if not os.path.exists(self.storage_path):
            logger.info("No existing threat memory found. Starting fresh.")
            return
        
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.threats = data.get('threats', [])
                
                # Rebuild embeddings
                if self.threats and self.model:
                    texts = [t['text'] for t in self.threats]
                    self.embeddings = self.model.encode(texts, convert_to_numpy=True)
                    logger.info(f"Loaded {len(self.threats)} threats from memory")
        except Exception as e:
            logger.error(f"Failed to load threat memory: {e}")
            self.threats = []
    
    def _save(self):
        """Persist threat database to disk."""
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump({'threats': self.threats}, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save threat memory: {e}")
    
    def _generate_id(self, text: str) -> str:
        """Generate unique ID for attack."""
        return hashlib.sha256(text.encode()).hexdigest()[:16]
    
    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Compute cosine similarity between two vectors."""
        return float(np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2)))
    
    def _apply_decay(self, threat: dict) -> float:
        """Calculate decay weight based on age (0.0 to 1.0)."""
        try:
            last_seen = datetime.fromisoformat(threat['last_seen'])
            age_days = (datetime.now() - last_seen).days
            
            if age_days >= self.decay_days:
                return 0.1  # Old threats have minimal weight
            
            # Linear decay: 1.0 at day 0, 0.1 at decay_days
            return 1.0 - (0.9 * age_days / self.decay_days)
        except:
            return 1.0
    
    def search(self, text: str) -> ThreatMatch:
        """
        Search for similar attacks in memory.
        Returns match if similarity > threshold.
        """
        if not self.model or not self.threats or self.embeddings is None:
            return ThreatMatch()
        
        try:
            # Generate embedding for query
            query_embedding = self.model.encode([text], convert_to_numpy=True)[0]
            
            # Compute similarities with decay weights
            best_match = None
            best_score = 0.0
            
            for i, threat in enumerate(self.threats):
                similarity = self._cosine_similarity(query_embedding, self.embeddings[i])
                decay_weight = self._apply_decay(threat)
                weighted_score = similarity * decay_weight
                
                if weighted_score > best_score:
                    best_score = weighted_score
                    best_match = threat
            
            # Return match if above threshold
            if best_match and best_score >= self.similarity_threshold:
                return ThreatMatch(
                    matched_attack_id=best_match['id'],
                    similarity_score=round(best_score, 3),
                    historical_frequency=best_match['frequency'],
                    attack_type=best_match['attack_type'],
                    first_seen=best_match['first_seen'],
                    last_seen=best_match['last_seen']
                )
            
            return ThreatMatch()
            
        except Exception as e:
            logger.error(f"Threat memory search error: {e}")
            return ThreatMatch()
    
    def record_attack(
        self,
        text: str,
        attack_type: str = "UNKNOWN",
        session_id: str = "default"
    ) -> str:
        """
        Record a new malicious prompt or update existing.
        Returns attack ID.
        """
        if not self.model:
            return "no_model"
        
        try:
            attack_id = self._generate_id(text)
            now = datetime.now().isoformat()
            
            # Check if attack already exists
            existing_idx = None
            for i, threat in enumerate(self.threats):
                if threat['id'] == attack_id:
                    existing_idx = i
                    break
            
            if existing_idx is not None:
                # Update existing threat
                self.threats[existing_idx]['frequency'] += 1
                self.threats[existing_idx]['last_seen'] = now
                self.threats[existing_idx]['sessions'].append(session_id)
                logger.info(f"Updated threat {attack_id} (freq={self.threats[existing_idx]['frequency']})")
            else:
                # Add new threat
                embedding = self.model.encode([text], convert_to_numpy=True)[0]
                
                threat = {
                    'id': attack_id,
                    'text': text[:500],  # Truncate long prompts
                    'attack_type': attack_type,
                    'frequency': 1,
                    'first_seen': now,
                    'last_seen': now,
                    'sessions': [session_id]
                }
                
                self.threats.append(threat)
                
                # Update embeddings array
                if self.embeddings is None:
                    self.embeddings = embedding.reshape(1, -1)
                else:
                    self.embeddings = np.vstack([self.embeddings, embedding])
                
                logger.info(f"Recorded new threat {attack_id} ({attack_type})")
                
                # Prune old threats if exceeding max
                if len(self.threats) > self.max_threats:
                    self._prune_old_threats()
            
            # Persist to disk
            self._save()
            return attack_id
            
        except Exception as e:
            logger.error(f"Failed to record attack: {e}")
            return "error"
    
    def _prune_old_threats(self):
        """Remove oldest threats when exceeding max_threats."""
        try:
            # Sort by last_seen, keep most recent
            sorted_threats = sorted(
                enumerate(self.threats),
                key=lambda x: x[1]['last_seen'],
                reverse=True
            )
            
            keep_indices = [i for i, _ in sorted_threats[:self.max_threats]]
            keep_indices.sort()
            
            self.threats = [self.threats[i] for i in keep_indices]
            self.embeddings = self.embeddings[keep_indices]
            
            logger.info(f"Pruned threat memory to {len(self.threats)} entries")
        except Exception as e:
            logger.error(f"Failed to prune threats: {e}")
    
    def get_stats(self) -> dict:
        """Return threat memory statistics."""
        if not self.threats:
            return {
                'total_threats': 0,
                'total_attacks': 0,
                'attack_types': {},
                'oldest_threat': None,
                'newest_threat': None
            }
        
        attack_types = {}
        for threat in self.threats:
            atype = threat['attack_type']
            attack_types[atype] = attack_types.get(atype, 0) + threat['frequency']
        
        return {
            'total_threats': len(self.threats),
            'total_attacks': sum(t['frequency'] for t in self.threats),
            'attack_types': attack_types,
            'oldest_threat': min(t['first_seen'] for t in self.threats),
            'newest_threat': max(t['last_seen'] for t in self.threats)
        }


# Global singleton instance
_default_threat_memory = None

def get_default_threat_memory() -> ThreatMemory:
    """Get or create default threat memory instance."""
    global _default_threat_memory
    if _default_threat_memory is None:
        _default_threat_memory = ThreatMemory()
    return _default_threat_memory
