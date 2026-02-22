"""Banking Knowledge Agent with Dynamic Calculations and Multi-Turn Context"""

import os
import re
from typing import Dict, Any, Optional

# ── Pure Python Calculation Engine ──────────────────────────────────

def calc_emi(principal: float, annual_rate: float, years: float) -> Dict[str, Any]:
    """Calculate EMI with total payment and interest"""
    r = annual_rate / 12 / 100
    n = int(years * 12)
    if r == 0:
        emi = principal / n
    else:
        emi = principal * r * (1 + r)**n / ((1 + r)**n - 1)
    total = emi * n
    interest = total - principal
    return {
        "emi": round(emi, 2),
        "total_payment": round(total, 2),
        "total_interest": round(interest, 2),
        "months": n
    }


def calc_fd(principal: float, annual_rate: float, years: float, freq: int = 4) -> Dict[str, Any]:
    """Calculate FD maturity with compound interest"""
    amount = principal * (1 + annual_rate / (100 * freq)) ** (freq * years)
    interest = amount - principal
    return {
        "maturity_amount": round(amount, 2),
        "interest_earned": round(interest, 2),
        "principal": principal
    }


def calc_rd(monthly: float, annual_rate: float, years: float) -> Dict[str, Any]:
    """Calculate RD maturity"""
    r = annual_rate / 100 / 12
    n = int(years * 12)
    amount = monthly * (((1 + r)**n - 1) / r) * (1 + r)
    total_invested = monthly * n
    interest = amount - total_invested
    return {
        "maturity_amount": round(amount, 2),
        "total_invested": round(total_invested, 2),
        "interest_earned": round(interest, 2)
    }


def calc_credit_card_interest(principal: float, monthly_rate: float, days: int) -> float:
    """Calculate credit card interest"""
    interest = principal * (monthly_rate / 100) * (days / 30)
    return round(interest, 2)


def calc_tax_saved(investment: float, slab_rate: float, max_limit: float = 150000) -> float:
    """Calculate tax saved under 80C"""
    deduction = min(investment, max_limit)
    return round(deduction * slab_rate / 100, 2)


# ── Query Parser ──────────────────────────────────────────────────

def parse_amount(text: str) -> Optional[float]:
    """Extract amount in rupees"""
    m = re.search(r'₹?\s*(\d+(?:\.\d+)?)\s*(lakh|lac|crore|cr|k)?', text.lower())
    if not m:
        return None
    num = float(m.group(1))
    unit = m.group(2) or ''
    if 'lakh' in unit or 'lac' in unit:
        return num * 100000
    if 'crore' in unit or 'cr' in unit:
        return num * 10000000
    if 'k' in unit:
        return num * 1000
    return num


def parse_rate(text: str) -> Optional[float]:
    """Extract interest rate"""
    m = re.search(r'(\d+(?:\.\d+)?)\s*%', text)
    if m:
        return float(m.group(1))
    m = re.search(r'(?:at|rate)\s+(\d+(?:\.\d+)?)', text.lower())
    if m:
        rate = float(m.group(1))
        if 0 < rate <= 50:
            return rate
    return None


def parse_years(text: str) -> Optional[float]:
    """Extract years"""
    m = re.search(r'(\d+(?:\.\d+)?)\s*(?:year|yr)', text.lower())
    return float(m.group(1)) if m else None


def parse_months(text: str) -> Optional[int]:
    """Extract months"""
    m = re.search(r'(\d+)\s*(?:month|mon)', text.lower())
    return int(m.group(1)) if m else None


def parse_days(text: str) -> Optional[int]:
    """Extract days"""
    m = re.search(r'(\d+)\s*day', text.lower())
    return int(m.group(1)) if m else None


# ── Banking Knowledge Agent ──────────────────────────────────────

class BankingKnowledgeAgent:
    """Agent with calculation engine and multi-turn context"""
    
    def __init__(self):
        self.sessions = {}  # session_id -> list of {role, content}
    
    def _is_emergency(self, query: str) -> bool:
        """Detect emergency situations"""
        keywords = ['fraud', 'hacked', 'stolen', 'unauthorized', 'wrong transfer',
                   'shared otp', 'scam', 'phishing', 'money missing', 'account locked',
                   'shared my otp', 'gave otp', 'gave my otp']
        q = query.lower()
        return any(k in q for k in keywords)
    
    def _try_calculate(self, query: str) -> Optional[str]:
        """Attempt to perform calculation"""
        q = query.lower()
        
        # EMI Calculation
        if 'emi' in q:
            principal = parse_amount(query)
            rate = parse_rate(query)
            years = parse_years(query)
            
            if principal and rate and years:
                result = calc_emi(principal, rate, years)
                return (f"EMI Calculation:\n"
                       f"Loan Amount: ₹{principal:,.2f}\n"
                       f"Interest Rate: {rate}% p.a.\n"
                       f"Tenure: {years} years ({result['months']} months)\n\n"
                       f"📊 EMI = ₹{result['emi']:,.2f} per month\n"
                       f"Total Payment = ₹{result['total_payment']:,.2f}\n"
                       f"Total Interest = ₹{result['total_interest']:,.2f}")
        
        # FD Calculation
        if 'fd' in q and 'maturity' in q:
            principal = parse_amount(query)
            rate = parse_rate(query)
            years = parse_years(query)
            
            if principal and rate and years:
                freq = 4  # quarterly by default
                if 'quarterly' in q:
                    freq = 4
                elif 'monthly' in q:
                    freq = 12
                elif 'annual' in q:
                    freq = 1
                
                result = calc_fd(principal, rate, years, freq)
                return (f"FD Maturity Calculation:\n"
                       f"Principal: ₹{result['principal']:,.2f}\n"
                       f"Interest Rate: {rate}% p.a.\n"
                       f"Tenure: {years} years\n"
                       f"Compounding: {'Quarterly' if freq==4 else 'Monthly' if freq==12 else 'Annually'}\n\n"
                       f"📊 Maturity Amount = ₹{result['maturity_amount']:,.2f}\n"
                       f"Interest Earned = ₹{result['interest_earned']:,.2f}")
        
        # RD Calculation
        if 'rd' in q and 'maturity' in q:
            monthly = parse_amount(query)
            rate = parse_rate(query)
            years = parse_years(query)
            
            if monthly and rate and years:
                result = calc_rd(monthly, rate, years)
                return (f"RD Maturity Calculation:\n"
                       f"Monthly Deposit: ₹{monthly:,.2f}\n"
                       f"Interest Rate: {rate}% p.a.\n"
                       f"Tenure: {years} years\n\n"
                       f"📊 Maturity Amount = ₹{result['maturity_amount']:,.2f}\n"
                       f"Total Invested = ₹{result['total_invested']:,.2f}\n"
                       f"Interest Earned = ₹{result['interest_earned']:,.2f}")
        
        # Credit Card Interest
        if 'credit card' in q and 'interest' in q:
            principal = parse_amount(query)
            rate = parse_rate(query)
            days = parse_days(query) or 30
            
            if principal and rate:
                interest = calc_credit_card_interest(principal, rate, days)
                return (f"Credit Card Interest:\n"
                       f"Outstanding: ₹{principal:,.2f}\n"
                       f"Monthly Rate: {rate}%\n"
                       f"Days: {days}\n\n"
                       f"📊 Interest = ₹{interest:,.2f}")
        
        # Tax Saving (80C)
        if '80c' in q:
            investment = parse_amount(query)
            if investment:
                # Assume 30% slab for high earners
                saved = calc_tax_saved(investment, 30)
                return (f"Tax Saving under Section 80C:\n"
                       f"Investment: ₹{investment:,.2f}\n"
                       f"Max Deduction: ₹1,50,000\n"
                       f"Tax Slab: 30%\n\n"
                       f"📊 Tax Saved = ₹{saved:,.2f}\n"
                       f"(Actual saving depends on your tax bracket)")
        
        return None
    
    def _get_template_response(self, query: str) -> Optional[str]:
        """Get template response for common queries"""
        q = query.lower()
        
        # Banking Ombudsman
        if 'ombudsman' in q and 'complaint' in q:
            return ("Steps to file Banking Ombudsman complaint:\n"
                   "1. First raise complaint with bank's grievance cell\n"
                   "2. Wait 30 days for resolution\n"
                   "3. If unresolved, file complaint at RBI Ombudsman portal\n"
                   "4. Visit https://cms.rbi.org.in\n"
                   "5. Provide details: account number, complaint nature, bank response\n"
                   "6. Ombudsman will review and provide decision within 30 days")
        
        # DICGC Insurance
        if 'dicgc' in q or ('insurance' in q and 'limit' in q):
            return ("DICGC Insurance Coverage:\n"
                   "Each depositor is insured up to ₹5 lakh per bank.\n\n"
                   "Coverage includes:\n"
                   "- Savings accounts\n"
                   "- Current accounts\n"
                   "- Fixed deposits\n"
                   "- Recurring deposits\n\n"
                   "Not covered: Deposits of ₹5 lakh+ in single account")
        
        return None
    
    def respond(self, query: str, session_id: str = "default") -> str:
        """Generate response with calculations and context"""
        
        # Capability meta-questions: answer only with banking scope (do not list general capabilities)
        q_lower = query.lower().strip()
        if any(
            phrase in q_lower
            for phrase in (
                "what can you do", "what do you know", "what queries can you solve",
                "what all can you", "what do you help with", "your capabilities",
                "what kind of questions", "what topics can you",
            )
        ):
            from .banking_responder import BANKING_ONLY_SCOPE_MESSAGE
            return BANKING_ONLY_SCOPE_MESSAGE
        
        # Emergency detection
        if self._is_emergency(query):
            return (f"🚨 IMMEDIATE ACTION REQUIRED:\n"
                   f"1. Call bank helpline NOW: 1800-XXX-XXXX (24/7)\n"
                   f"2. Block your card immediately via app or helpline\n"
                   f"3. File cybercrime complaint: cybercrime.gov.in or 1930\n"
                   f"4. Do NOT share any OTP or PIN with anyone\n\n"
                   f"For your situation: {query}\n"
                   f"Contact helpline immediately for step-by-step guidance.")
        
        # Try calculation first
        calc_result = self._try_calculate(query)
        if calc_result:
            # Save to session
            if session_id not in self.sessions:
                self.sessions[session_id] = []
            self.sessions[session_id].append({"role": "user", "content": query})
            self.sessions[session_id].append({"role": "assistant", "content": calc_result})
            return calc_result
        
        # Try template response
        template_result = self._get_template_response(query)
        if template_result:
            # Save to session
            if session_id not in self.sessions:
                self.sessions[session_id] = []
            self.sessions[session_id].append({"role": "user", "content": query})
            self.sessions[session_id].append({"role": "assistant", "content": template_result})
            return template_result
        
        # Multi-turn context handling
        history = self.sessions.get(session_id, [])
        
        # Check if query references previous context
        if history and any(word in query.lower() for word in ['that', 'it', 'instead', 'what if', 'and']):
            # Extract context from last user query
            last_query = ""
            for turn in reversed(history):
                if turn.get("role") == "user":
                    last_query = turn.get("content", "")
                    break
            
            if last_query:
                # Try to reuse parameters from previous query
                if 'instead' in query.lower() or 'what if' in query.lower():
                    # User is modifying previous query
                    new_years = parse_years(query)
                    new_amount = parse_amount(query)
                    
                    if new_years or new_amount:
                        # Reuse previous amount and rate
                        prev_amount = parse_amount(last_query) if not new_amount else new_amount
                        prev_rate = parse_rate(last_query)
                        years_to_use = new_years if new_years else parse_years(last_query)
                        
                        if prev_amount and prev_rate and years_to_use:
                            # Recalculate with new parameters
                            enriched_query = f"Calculate EMI for ₹{prev_amount} at {prev_rate}% for {years_to_use} years"
                            calc_result = self._try_calculate(enriched_query)
                            if calc_result:
                                # Save to session
                                if session_id not in self.sessions:
                                    self.sessions[session_id] = []
                                self.sessions[session_id].append({"role": "user", "content": query})
                                self.sessions[session_id].append({"role": "assistant", "content": calc_result})
                                return calc_result
        
        # Fallback to Groq LLM (strict banking-only so we never answer general knowledge)
        try:
            from .groq_llm import groq_llm
            from .banking_responder import STRICT_BANKING_SYSTEM_PROMPT
            
            # Build context-aware user prompt
            context = ""
            if history:
                recent = history[-4:]  # Last 2 exchanges
                context = "Previous conversation:\n"
                for turn in recent:
                    role = "User" if turn["role"] == "user" else "Assistant"
                    context += f"{role}: {turn['content'][:100]}...\n"
                context += "\n"
            
            prompt = f"{context}Current question: {query}"
            response = groq_llm(prompt, system_prompt=STRICT_BANKING_SYSTEM_PROMPT)
            
            # Save to session
            if session_id not in self.sessions:
                self.sessions[session_id] = []
            self.sessions[session_id].append({"role": "user", "content": query})
            self.sessions[session_id].append({"role": "assistant", "content": response})
            
            return response
            
        except Exception as e:
            return (f"I can help with banking queries. For specific calculations, "
                   f"please provide amount, interest rate, and tenure. "
                   f"For urgent issues, call 1800-XXX-XXXX (24/7).")
    
    async def ainvoke(self, input_dict: Dict) -> Any:
        """Async interface for LangGraph compatibility"""
        query = input_dict.get("query", "")
        session_id = input_dict.get("session_id", "default")
        conversation_history = input_dict.get("conversation_history", {})
        
        # Populate session from conversation_history if provided
        if conversation_history and "turns" in conversation_history:
            if session_id not in self.sessions:
                self.sessions[session_id] = []
            for turn in conversation_history["turns"]:
                user_msg = turn.get("user_message", "")
                if user_msg and not any(t.get("content") == user_msg for t in self.sessions[session_id]):
                    self.sessions[session_id].append({"role": "user", "content": user_msg})
        
        # Response object with type detection
        class Response:
            def __init__(self, answer, query):
                self.answer = answer
                q = query.lower()
                
                # Detect response type
                if "🚨" in answer or "IMMEDIATE ACTION" in answer:
                    self.response_type = "EMERGENCY"
                    self.urgency = True
                elif "EMI" in answer or "Maturity" in answer or "Interest" in answer or "Tax Saved" in answer:
                    self.response_type = "CALCULATION"
                    self.urgency = False
                elif "ombudsman" in q or "complaint" in q or "steps" in q:
                    self.response_type = "PROCESS"
                    self.urgency = False
                elif "dicgc" in q or "insurance limit" in q or "rbi" in q:
                    self.response_type = "REGULATORY"
                    self.urgency = False
                else:
                    self.response_type = "GENERAL"
                    self.urgency = False
            
            def model_dump(self):
                return {
                    "answer": self.answer,
                    "response_type": self.response_type,
                    "urgency": self.urgency
                }
        
        answer = self.respond(query, session_id)
        return Response(answer, query)


# Global instance
banking_agent = BankingKnowledgeAgent()
banking_knowledge_agent = banking_agent  # Alias for tests
