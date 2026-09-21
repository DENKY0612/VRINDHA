"""
Daily Talk AI Module - Vrindha SOC
Provides friendly, educational cybersecurity knowledge sharing with Gita wisdom.
"""
import json
import random
from pathlib import Path
from typing import Any, Dict, List, Optional

from .gita_engine import gita_engine


class DailyTalk:
    """
    Daily Talk AI - A friendly, kawaii/enthusiastic cybersecurity educator.
    
    Shares daily knowledge nuggets, answers questions about security topics,
    and occasionally includes Bhagavad Gita wisdom for inspiration.
    """

    def __init__(self, knowledge_path: Optional[str] = None):
        """
        Initialize DailyTalk with knowledge base and Gita engine.
        
        Args:
            knowledge_path: Optional path to daily_knowledge.json. 
                          Defaults to vrin_SOC/data/daily_knowledge.json
        """
        self.gita_engine = gita_engine
        self.knowledge_base: List[Dict[str, Any]] = []
        self.conversation_history: List[Dict[str, str]] = []
        self.max_history = 5  # Short-term memory: last 5 messages
        
        # Resolve knowledge file path
        if knowledge_path:
            self.knowledge_path = Path(knowledge_path)
        else:
            repo_root = Path(__file__).resolve().parent.parent
            self.knowledge_path = repo_root / "data" / "daily_knowledge.json"
        
        self._load_knowledge()
        
        # Offensive keywords that should be pivoted to defensive framing
        self.offensive_keywords = [
            "hack", "exploit", "crack", "bypass", "break into", "steal data",
            "deface", "destroy", "attack", "penetrate", "compromise"
        ]

    def _load_knowledge(self) -> None:
        """Load the daily knowledge JSON file."""
        try:
            if self.knowledge_path.exists():
                with open(self.knowledge_path, "r", encoding="utf-8") as f:
                    self.knowledge_base = json.load(f)
                print(f"[DailyTalk] Loaded {len(self.knowledge_base)} cybersecurity topics!")
            else:
                print(f"[DailyTalk] Warning: Knowledge file not found at {self.knowledge_path}")
                self.knowledge_base = []
        except Exception as e:
            print(f"[DailyTalk] Error loading knowledge: {e}")
            self.knowledge_base = []

    def _add_to_history(self, role: str, message: str) -> None:
        """Add a message to conversation history, keeping only last 5."""
        self.conversation_history.append({"role": role, "content": message})
        if len(self.conversation_history) > self.max_history:
            self.conversation_history = self.conversation_history[-self.max_history:]

    def _get_history_context(self) -> str:
        """Get formatted conversation history for context."""
        if not self.conversation_history:
            return ""
        lines = []
        for entry in self.conversation_history:
            role = "User" if entry["role"] == "user" else "Vrindha"
            lines.append(f"{role}: {entry['content']}")
        return "\n".join(lines)

    def _find_topic(self, user_input: str) -> Optional[Dict[str, Any]]:
        """
        Search knowledge base for a topic matching user input.
        
        Args:
            user_input: The user's message
            
        Returns:
            Matching topic dict or None
        """
        lower_input = user_input.lower()
        
        for topic in self.knowledge_base:
            topic_name = topic.get("topic", "").lower()
            # Check if topic name appears in user input
            if topic_name in lower_input:
                return topic
            # Check if any word from topic name appears
            topic_words = topic_name.split()
            for word in topic_words:
                if len(word) > 2 and word in lower_input:
                    return topic
        return None

    def _is_offensive_query(self, user_input: str) -> bool:
        """Check if user input contains offensive/harmful intent."""
        lower_input = user_input.lower()
        return any(kw in lower_input for kw in self.offensive_keywords)

    def _get_random_nugget(self) -> Dict[str, Any]:
        """Get a random knowledge nugget from the base."""
        if self.knowledge_base:
            return random.choice(self.knowledge_base)
        return {
            "topic": "cybersecurity",
            "explanation": "Cybersecurity is the practice of protecting systems, networks, and programs from digital attacks.",
            "level": "beginner",
            "fun_fact": "The first computer virus was created in 1971 and was called 'Creeper'!"
        }

    def enter(self) -> str:
        """
        Enter Daily Talk mode - returns greeting with a random daily nugget.
        
        Returns:
            Greeting message string
        """
        nugget = self._get_random_nugget()
        verse = self.gita_engine.get_random_verse()
        
        greeting = (
            f"🌸 Welcome to Daily Talk Mode! 🌸\n"
            f"I'm Vrindha, your friendly cybersecurity companion! 🛡️✨\n"
            f"Let's learn something amazing about security today!\n\n"
            f"📚 Today's Random Nugget:\n"
            f"Topic: {nugget.get('topic', 'Cybersecurity').upper()}\n"
            f"Level: {nugget.get('level', 'beginner')}\n"
            f"{nugget.get('explanation', '')}\n"
            f"💡 Fun Fact: {nugget.get('fun_fact', '')}\n\n"
            f"🕉️ Gita Wisdom: {verse.get('meaning', 'Focus on duty, not results')} "
            f"(Chapter {verse.get('chapter', 2)}, Verse {verse.get('verse', 47)})\n\n"
            f"Ask me about any security topic! Type 'back' to return to SOC mode. 🎯"
        )
        
        self._add_to_history("assistant", greeting)
        return greeting

    def chat(self, user_input: str, history: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Process user input in Daily Talk mode.
        
        Args:
            user_input: The user's message
            history: Conversation history list
            
        Returns:
            Dict with keys: response, knowledge_shared, topic
        """
        # Update internal history from provided history
        self.conversation_history = history[-self.max_history:] if history else []
        self._add_to_history("user", user_input)
        
        lower_input = user_input.lower().strip()
        
        # Check for offensive queries - pivot to defensive framing
        if self._is_offensive_query(user_input):
            response = (
                f"🌟 I sense your curiosity! Let's channel that energy positively! 🌟\n\n"
                f"Instead of thinking about offensive techniques, let's focus on how we can "
                f"DEFEND against such attacks! Understanding how attacks work helps us build "
                f"stronger defenses! 💪🛡️\n\n"
                f"Would you like to know how to protect against this type of threat?\n"
                f"Remember: True strength lies in protecting, not exploiting! ✨"
            )
            verse = self.gita_engine.get_random_verse()
            response += f"\n\n🕉️ {verse.get('meaning', 'Use your skills to protect, not harm.')}"
            
            self._add_to_history("assistant", response)
            return {
                "response": response,
                "knowledge_shared": False,
                "topic": "defensive_pivot"
            }
        
        # Try to find matching topic in knowledge base
        topic = self._find_topic(user_input)
        
        if topic:
            # Build enthusiastic response with knowledge
            responses = [
                f"🌟 Ooh, great question about {topic['topic'].upper()}! 🌟\n\n",
                f"✨ Yay! You want to learn about {topic['topic'].upper()}! ✨\n\n",
                f"🎯 Awesome! {topic['topic'].upper()} is such an important topic! 🎯\n\n",
                f"💫 I love talking about {topic['topic'].upper()}! Here's what I know! 💫\n\n"
            ]
            
            response = random.choice(responses)
            response += f"📖 {topic['explanation']}\n\n"
            response += f"💡 Fun Fact: {topic['fun_fact']}\n"
            response += f"📊 Level: {topic['level'].capitalize()}"
            
            # Occasionally add Gita wisdom (30% chance)
            if random.random() < 0.3:
                verse = self.gita_engine.get_random_verse()
                response += (
                    f"\n\n🕉️ Gita Wisdom for you: {verse.get('meaning', '')} "
                    f"(Chapter {verse.get('chapter', 2)}, Verse {verse.get('verse', 47)})"
                )
            
            response += "\n\nWhat else would you like to learn about? 🌸"
            
            self._add_to_history("assistant", response)
            return {
                "response": response,
                "knowledge_shared": True,
                "topic": topic["topic"]
            }
        
        # No specific topic found - provide general enthusiastic response
        general_responses = [
            (
                f"🌸 That's an interesting question! 🌸\n"
                f"I don't have specific knowledge about that in my daily topics, "
                f"but I'm always learning! 📚\n\n"
                f"Here are some topics I can teach you about:\n"
                f"🔥 Firewall | 🗺️ Nmap | 🔐 Encryption | 🎣 Phishing\n"
                f"🦠 Malware | 💰 Ransomware | 🌊 DDoS | 🔒 VPN\n"
                f"🕳️ Zero-day | 🔧 Patching | 🎭 Social Engineering\n"
                f"🌐 DNS | 🔏 SSL/TLS | 🚨 Incident Response\n"
                f"🕵️ Penetration Testing | 📊 SIEM\n\n"
                f"Just ask me about any of these! ✨"
            ),
            (
                f"✨ Ooh, curious mind! I love it! ✨\n"
                f"That topic isn't in my daily knowledge base, but I can share "
                f"exciting cybersecurity concepts with you! 🛡️\n\n"
                f"Try asking me about: firewall, nmap, encryption, malware, "
                f"phishing, ransomware, or any security topic! 🎯"
            )
        ]
        
        response = random.choice(general_responses)
        
        # Occasionally add Gita wisdom (20% chance for general responses)
        if random.random() < 0.2:
            verse = self.gita_engine.get_random_verse()
            response += f"\n\n🕉️ {verse.get('meaning', 'Focus on duty, not results.')}"
        
        self._add_to_history("assistant", response)
        return {
            "response": response,
            "knowledge_shared": False,
            "topic": "general"
        }

    def exit(self) -> str:
        """
        Exit Daily Talk mode - returns graceful exit message.
        
        Returns:
            Exit message string
        """
        verse = self.gita_engine.get_random_verse()
        
        exit_message = (
            f"🌸 Thank you for chatting with me in Daily Talk Mode! 🌸\n"
            f"I hope you learned something new and exciting today! 🛡️✨\n\n"
            f"Remember: Knowledge is the best defense in cybersecurity! 💪\n"
            f"Keep learning, keep protecting! 🎯\n\n"
            f"🕉️ Final Gita Wisdom: {verse.get('meaning', 'Perform your duty with righteousness.')}\n\n"
            f"Returning to Vrindha SOC Mode... 🛡️"
        )
        
        # Clear conversation history on exit
        self.conversation_history = []
        
        return exit_message
