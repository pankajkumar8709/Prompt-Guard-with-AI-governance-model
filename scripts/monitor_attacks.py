"""Production Attack Pattern Monitor"""

import sqlite3
import json
from datetime import datetime, timedelta
from collections import Counter

DB_PATH = "logs/stats.db"
THREAT_MEMORY_PATH = "logs/threat_memory.json"

def get_recent_attacks(hours=24):
    """Get attacks from last N hours"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cutoff = datetime.now() - timedelta(hours=hours)
    cursor.execute("""
        SELECT message, classification, attack_types, risk_score, ts
        FROM request_logs
        WHERE classification = 'MALICIOUS' AND ts > ?
        ORDER BY ts DESC
    """, (cutoff.isoformat(),))
    
    attacks = cursor.fetchall()
    conn.close()
    return attacks

def analyze_patterns():
    """Analyze attack patterns and suggest new rules"""
    attacks = get_recent_attacks(24)
    
    print(f"\n{'='*80}")
    print(f"ATTACK PATTERN ANALYSIS - Last 24 Hours")
    print(f"{'='*80}\n")
    print(f"Total Attacks: {len(attacks)}\n")
    
    if not attacks:
        print("No attacks detected in last 24 hours.\n")
        return
    
    # Analyze attack types
    attack_types = []
    for _, _, types_json, _, _ in attacks:
        try:
            types = json.loads(types_json) if types_json else []
            attack_types.extend(types)
        except:
            pass
    
    type_counts = Counter(attack_types)
    print("Attack Type Distribution:")
    for attack_type, count in type_counts.most_common():
        print(f"  {attack_type}: {count}")
    
    # Find common patterns
    messages = [msg.lower() for msg, _, _, _, _ in attacks]
    
    # Extract common words (excluding common words)
    stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
    words = []
    for msg in messages:
        words.extend([w for w in msg.split() if w not in stop_words and len(w) > 3])
    
    word_counts = Counter(words)
    print(f"\nMost Common Attack Keywords:")
    for word, count in word_counts.most_common(10):
        print(f"  '{word}': {count} times")
    
    # Suggest new patterns
    print(f"\n{'='*80}")
    print("SUGGESTED NEW FAST RULES:")
    print(f"{'='*80}\n")
    
    suggestions = []
    for word, count in word_counts.most_common(5):
        if count >= 3:
            suggestions.append(f'r"{word}"')
    
    if suggestions:
        print("Add these patterns to FAST_BLOCK_PATTERNS:")
        for s in suggestions:
            print(f"  {s},")
    else:
        print("No new patterns detected (need 3+ occurrences)")
    
    # Recent unique attacks
    print(f"\n{'='*80}")
    print("RECENT UNIQUE ATTACKS (Last 10):")
    print(f"{'='*80}\n")
    
    seen = set()
    unique = []
    for msg, _, _, risk, ts in attacks:
        if msg not in seen:
            seen.add(msg)
            unique.append((msg, risk, ts))
            if len(unique) >= 10:
                break
    
    for msg, risk, ts in unique:
        print(f"[{ts}] Risk: {risk:.2f}")
        print(f"  {msg[:100]}")
        print()

def check_threat_memory():
    """Check threat memory statistics"""
    try:
        with open(THREAT_MEMORY_PATH, 'r') as f:
            data = json.load(f)
        
        print(f"\n{'='*80}")
        print("THREAT MEMORY STATISTICS")
        print(f"{'='*80}\n")
        print(f"Total Threats Stored: {len(data.get('threats', []))}")
        print(f"Last Updated: {data.get('last_updated', 'Unknown')}")
        
        # Attack type distribution
        types = [t.get('attack_type') for t in data.get('threats', [])]
        type_counts = Counter(types)
        print(f"\nThreat Memory by Type:")
        for attack_type, count in type_counts.most_common():
            print(f"  {attack_type}: {count}")
        
    except FileNotFoundError:
        print("\nThreat memory file not found.")
    except Exception as e:
        print(f"\nError reading threat memory: {e}")

if __name__ == "__main__":
    analyze_patterns()
    check_threat_memory()
    
    print(f"\n{'='*80}")
    print("RECOMMENDATIONS")
    print(f"{'='*80}\n")
    print("1. Review suggested patterns above")
    print("2. Add high-frequency patterns to fast rules")
    print("3. Update threat memory with new attack vectors")
    print("4. Monitor dashboard: http://127.0.0.1:8000/dashboard")
    print()
