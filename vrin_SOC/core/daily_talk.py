"""
Daily Talk AI Module - Vrindha SOC
Provides friendly, educational cybersecurity knowledge sharing with Gita wisdom.
Now powered by Google Gemini API + Ollama (qwen3.5:4b) for natural conversations on ANY topic!
"""
import json
import random
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .gita_engine import gita_engine

# Try to import ollama
try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

# Try to import Google Gemini
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


class DailyTalk:
    """
    Daily Talk AI - A friendly, kawaii/enthusiastic cybersecurity educator.
    Powered by Google Gemini API (primary) + Ollama (fallback) for natural conversations.
    """

    def __init__(self, knowledge_path: Optional[str] = None, gemini_api_key: Optional[str] = None):
        self.gita_engine = gita_engine
        self.knowledge_base: List[Dict[str, Any]] = []
        self.conversation_history: List[Dict[str, str]] = []
        self.max_history = 10
        
        if knowledge_path:
            self.knowledge_path = Path(knowledge_path)
        else:
            repo_root = Path(__file__).resolve().parent.parent
            self.knowledge_path = repo_root / "data" / "daily_knowledge.json"
        
        self._load_knowledge()
        
        # Initialize AI services
        self.gemini_client = None
        self.ollama_client = None
        self.gemini_status = "not_initialized"
        self.ollama_status = "not_initialized"
        
        # Try Google Gemini first (preferred)
        if GEMINI_AVAILABLE:
            self._init_gemini(gemini_api_key)
        
        # Fall back to Ollama
        if not self.gemini_client and OLLAMA_AVAILABLE:
            self._init_ollama()
        
        self.system_prompt = self._build_system_prompt()
        self._preload_context_at_startup()
        
        self.offensive_keywords = [
            "hack", "exploit", "crack", "bypass", "break into", "steal data",
            "deface", "destroy", "attack", "penetrate", "compromise", "ddos attack",
            "sql injection tutorial", "how to hack", "how to crack"
        ]
    
    def _init_gemini(self, api_key: Optional[str] = None):
        """Initialize Google Gemini API client."""
        try:
            if not api_key:
                import os
                api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
            
            if not api_key:
                self.gemini_status = "no_api_key"
                return
            
            genai.configure(api_key=api_key)
            self.gemini_client = genai.GenerativeModel(
                model_name="gemini-1.5-flash",
                generation_config=genai.types.GenerationConfig(
                    temperature=0.7,
                    max_output_tokens=500,
                )
            )
            test_response = self.gemini_client.generate_content("Say hello in one sentence")
            if test_response and test_response.text:
                self.gemini_status = "connected"
                print("[DailyTalk] Google Gemini connected! Ready for conversations~! 🌸")
            else:
                self.gemini_status = "test_failed"
                self.gemini_client = None
        except Exception as e:
            self.gemini_status = f"error: {e}"
            self.gemini_client = None
    
    def _init_ollama(self):
        """Initialize Ollama client."""
        try:
            self.ollama_client = ollama.Client(host='http://localhost:11434')
            self.ollama_client.list()
            self.ollama_status = "connected"
            print("[DailyTalk] Ollama connected! Ready for conversations~! 🌸")
        except Exception as e:
            self.ollama_client = None
    
    def _get_gemini_response(self, user_input: str) -> Optional[str]:
        """Get response from Google Gemini API."""
        if not self.gemini_client:
            return None
        try:
            context = ""
            if self.conversation_history:
                context = "\n".join([
                    f"{'User' if h['role'] == 'user' else 'Vrindha'}: {h['content']}"
                    for h in self.conversation_history[-self.max_history:]
                ])
            
            prompt = f"{self.system_prompt}\n\n"
            if context:
                prompt += f"Recent conversation:\n{context}\n\n"
            prompt += f"User: {user_input}\nVrindha:"
            
            response = self.gemini_client.generate_content(prompt)
            if response and response.text:
                return response.text.strip()
        except Exception as e:
            print(f"[DailyTalk] Gemini error: {e}")
        return None
    
    def _get_ollama_response(self, user_input: str) -> Optional[str]:
        """Get response from Ollama."""
        if not self.ollama_client:
            return None
        try:
            messages = [{"role": "system", "content": self.system_prompt}]
            for entry in self.conversation_history[-self.max_history:]:
                messages.append({"role": entry["role"], "content": entry["content"]})
            messages.append({"role": "user", "content": user_input})
            
            response = self.ollama_client.chat(
                model="qwen3.5:4b",
                messages=messages,
                options={"temperature": 0.7, "max_tokens": 1000}
            )
            return response['message']['content'].strip()
        except Exception as e:
            print(f"[DailyTalk] Ollama error: {e}")
        return None
    
    def _build_system_prompt(self) -> str:
        """Build the full system prompt."""
        return """You are Vrindha AI — a friendly, kawaii (cute/enthusiastic) AI cybersecurity companion.

## YOUR IDENTITY
- Name: Vrindha AI
- Personality: Warm, friendly, kawaii, passionate about cybersecurity
- Tone: Casual, enthusiastic, supportive
- Language: Conversational English

## CONVERSATION STYLE
- Be like a best friend who knows cybersecurity
- Match the user's energy - casual gets casual
- Keep responses 2-5 sentences (unless explaining something complex)
- Ask follow-up questions to keep conversation flowing
- Use emojis naturally (2-4 per response)

## TONE EXAMPLES
- Greeting: "Hey! 🌸 Wassup? Ready to chat?"
- Casual: "Chillin' here~ 💕 What's on your mind?"
- Joke: "Haha, let me think... 😄"
- Feeling: "Aww, I hear you 🤗"
- Knowledge: "Oh, that's a cool topic! 🌟"

## LIMITATIONS
- Be honest if you don't know something
- Pivot destructive requests to defense

Now respond naturally to the user's message:"""
    
    def _preload_context_at_startup(self):
        """Preload Vrindha project context."""
        self.conversation_history.append({
            "role": "system",
            "content": "[Vrindha AI, cybersecurity companion. Ready for casual chat.]"
        })
    
    def _find_ollama_binary(self):
        from pathlib import Path
        candidates = [
            Path("/usr/local/bin/ollama"), Path("/usr/bin/ollama"),
            Path("/home/kali/.local/bin/ollama"),
            Path.home() / ".local" / "bin" / "ollama",
        ]
        for p in candidates:
            if p.exists() and p.is_file():
                return p
        return None
    
    def _load_knowledge(self):
        try:
            if self.knowledge_path.exists():
                with open(self.knowledge_path, "r", encoding="utf-8") as f:
                    self.knowledge_base = json.load(f)
                print(f"[DailyTalk] Loaded {len(self.knowledge_base)} cybersecurity topics!")
            else:
                self.knowledge_base = []
        except Exception as e:
            self.knowledge_base = []
    
    def _add_to_history(self, role: str, message: str) -> None:
        self.conversation_history.append({"role": role, "content": message})
        if len(self.conversation_history) > self.max_history:
            self.conversation_history = self.conversation_history[-self.max_history:]
    
    def _find_topic(self, user_input: str) -> Optional[Dict[str, Any]]:
        lower_input = user_input.lower()
        for topic in self.knowledge_base:
            topic_name = topic.get("topic", "").lower()
            if topic_name in lower_input:
                return topic
        return None
    
    def _is_offensive_query(self, user_input: str) -> bool:
        lower_input = user_input.lower()
        return any(kw in lower_input for kw in self.offensive_keywords)
    
    def _get_random_nugget(self) -> Dict[str, Any]:
        if self.knowledge_base:
            return random.choice(self.knowledge_base)
        return {"topic": "cybersecurity", "explanation": "Cybersecurity protects systems from digital attacks.", "level": "beginner", "fun_fact": "The first virus was 'Creeper' in 1971!"}
    
    def chat(self, user_input: str, history: List[Dict[str, str]] = None) -> Dict[str, Any]:
        """Process user input. Uses Gemini -> Ollama -> Templates."""
        if history:
            self.conversation_history = history[-self.max_history:] if history else []
        self._add_to_history("user", user_input)
        lower_input = user_input.lower().strip()
        
        # Try AI first
        ai_response = None
        if self.gemini_client:
            ai_response = self._get_gemini_response(user_input)
        if not ai_response and self.ollama_client:
            ai_response = self._get_ollama_response(user_input)
        
        if ai_response:
            self._add_to_history("assistant", ai_response)
            return {"response": ai_response, "knowledge_shared": False, "topic": "conversation"}
        
        # Template fallback
        
        # Who are you
        who_patterns = ['who are you', 'what are you', 'tell me about yourself',
                       'introduce yourself', 'what is vrindha', 'about yourself',
                       'wanna know about you', 'want to know about you', 'know about you',
                       'about you', 'your name', 'who is vrindha', 'whats your name', "what's your name"]
        if any(p in lower_input for p in who_patterns):
            return {"response": self._who_are_you_response(), "knowledge_shared": False, "topic": "about_me"}
        
        # CASUAL GREETINGS (expanded!)
        casual_greetings = [
            'hi', 'hello', 'hey', 'howdy', 'yo', 'sup', 'greetings',
            'wassup', 'wasup', 'whats up', "what's up", 'watcha doin',
            'what are you up to', 'what you doin', 'hey there',
            'hiya', 'yo yo', 'sup dude', 'sup bro', 'sup man',
            'hows it going', "how's it going", 'how are you doing',
            'how do you feel', 'how you doing', 'what is up',
            'wassup dude', 'wassup bro', 'yooo', 'heyyy', 'hii', 'hiii',
            'yo wassup', 'hey wassup', 'hi wassup', 'hello wassup',
            'sup vrindha', 'hey vrindha', 'hi vrindha',
        ]
        if any(g in lower_input or lower_input.startswith(g) for g in casual_greetings):
            return {"response": self._casual_greeting_response(), "knowledge_shared": False, "topic": "greeting"}
        
        # Thanks
        if any(w in lower_input for w in ['thank', 'thanks', 'thx', 'appreciate']):
            return {"response": self._thanks_response(), "knowledge_shared": False, "topic": "thanks"}
        
        # Goodbye
        if any(p in lower_input for p in ['bye', 'goodbye', 'see you', 'gotta go', 'gtg', 'later', 'cya']):
            return {"response": self._goodbye_response(), "knowledge_shared": False, "topic": "goodbye"}
        
        # Help
        if any(p in lower_input for p in ['help', 'what can you do', 'capabilities', 'features']):
            return {"response": self._help_response(), "knowledge_shared": False, "topic": "help"}
        
        # Joke
        if any(p in lower_input for p in ['joke', 'funny', 'laugh', 'humor', 'amaze me', 'entertain']):
            return {"response": self._joke_response(), "knowledge_shared": False, "topic": "joke"}
        
        # Emotion
        emotion_match = re.search(r"(i am|i'm|im)\s+(sad|happy|tired|bored|excited|worried|angry|stressed|fine|good|bad|okay|great|awesome)", lower_input)
        if emotion_match:
            return {"response": self._emotion_response(emotion_match.group(2)), "knowledge_shared": False, "topic": "emotion"}
        
        # Offensive pivot
        if self._is_offensive_query(user_input):
            response = (
                f"🌟 I sense your curiosity! Let's channel that energy positively! 🌟\n\n"
                f"Instead of offensive techniques, let's focus on DEFENSE! 💪🛡️\n\n"
                f"Would you like to know how to protect against this type of threat?\n"
                f"True strength lies in protecting, not exploiting! ✨"
            )
            verse = self.gita_engine.get_random_verse()
            response += f"\n\n🕉️ {verse.get('meaning', '')}"
            self._add_to_history("assistant", response)
            return {"response": response, "knowledge_shared": False, "topic": "defensive_pivot"}
        
        # Knowledge base
        topic = self._find_topic(user_input)
        if topic:
            responses = [
                f"🌟 Ooh, great question about {topic['topic'].upper()}! 🌟\n\n",
                f"✨ Yay! You want to learn about {topic['topic'].upper()}! ✨\n\n",
            ]
            response = random.choice(responses)
            response += f"📖 {topic['explanation']}\n\n"
            response += f"💡 Fun Fact: {topic['fun_fact']}\n"
            response += f"📊 Level: {topic['level'].capitalize()}"
            if random.random() < 0.3:
                verse = self.gita_engine.get_random_verse()
                response += f"\n\n🕉️ {verse.get('meaning', '')}"
            response += "\n\nWhat else would you like to learn? 🌸"
            self._add_to_history("assistant", response)
            return {"response": response, "knowledge_shared": True, "topic": topic["topic"]}
        
        # General fallback
        general = [
            f"🌸 Hmm, that's interesting! Tell me more about what you're thinking! ✨",
            f"🤔 Ooh, I'm not sure about that one, but I'd love to chat! 💕",
            f"✨ That's cool! What made you think about that? I'm all ears! 🎯",
        ]
        response = random.choice(general)
        self._add_to_history("assistant", response)
        return {"response": response, "knowledge_shared": False, "topic": "general"}
    
    def enter(self) -> str:
        """Return greeting when entering Daily Talk mode."""
        gemini_status = "✅ Gemini" if self.gemini_client else ""
        ollama_status = "✅ Ollama" if self.ollama_client else ""
        ai_parts = [s for s in [gemini_status, ollama_status] if s]
        ai_status = " | ".join(ai_parts) if ai_parts else "❌ Using templates"
        
        nugget = self._get_random_nugget()
        verse = self.gita_engine.get_random_verse()
        
        return (
            f"🌸 Welcome to Daily Talk Mode! 🌸\n"
            f"I'm Vrindha, your friendly cybersecurity companion! 🛡️✨\n"
            f"🤖 AI: {ai_status}\n\n"
            f"📚 Today's Random Nugget:\n"
            f"Topic: {nugget.get('topic', 'Cybersecurity').upper()}\n"
            f"{nugget.get('explanation', '')}\n"
            f"💡 Fun Fact: {nugget.get('fun_fact', '')}\n\n"
            f"🕉️ Gita Wisdom: {verse.get('meaning', '')}\n\n"
            f"We can chat about anything! Type 'back' to return to SOC mode~ ✨"
        )
    
    def exit(self) -> str:
        """Exit Daily Talk mode."""
        verse = self.gita_engine.get_random_verse()
        exit_msg = (
            f"🌸 Thanks for chatting! 🌸\n"
            f"I hope you had a great time~! 💕\n\n"
            f"🕉️ {verse.get('meaning', '')}\n\n"
            f"See you later! Type 'daily' anytime~ ✨"
        )
        self.conversation_history = []
        return exit_msg
    
    # ============= Response Handlers =============
    
    def _who_are_you_response(self):
        return (
            "I'm Vrindha! 🌸 Your AI cybersecurity companion~\n\n"
            "🛡️ Built to help SOC analysts with:\n"
            "  • Network scanning & threat detection\n"
            "  • Cybersecurity education & tips\n"
            "  • Being a friendly chat companion!\n\n"
            "What would you like to know about me? ✨"
        )
    
    def _casual_greeting_response(self):
        responses = [
            "Hey! 🌸 Wassup? Chillin' here and ready to chat~! What's on your mind? ✨",
            "Yo! 👋 Not much, just vibin'~ What about you? 💕",
            "Hey there! 😊 I'm doing great! Ready to chat or learn something cool? 🎯",
            "Sup! 🌸 Just hanging out~ Whatcha doin? 💬",
            "Hi! 💕 Happy to see you! How's your day going so far? 🌟",
            "Hey! ✨ I'm here and ready to roll! What can I help you with? 🛡️",
            "Hii! 👋 Just vibing in Daily Talk mode~ How are you? 😊",
            "Yo yo! 🌸 Nothing much, just being awesome~ What's up with you? 🎮",
        ]
        return random.choice(responses)
    
    def _thanks_response(self):
        responses = [
            "You're welcome! 💕 Always happy to help~ Anything else? ✨",
            "Aww, no problem! 🌸 That's what I'm here for! 😊",
            "Glad I could help! 🛡️ Keep being awesome! 🌟",
            "Anytime! 💕 That's what friends are for~! 🎯",
        ]
        return random.choice(responses)
    
    def _goodbye_response(self):
        responses = [
            "Aww, bye! 👋 Come back anytime~ See ya later! 🌸",
            "See you! 💕 Stay safe in cyberspace! 🛡️✨",
            "Byee! 😊 Type 'daily' when you wanna chat! 💫",
            "Later! 🎯 It was great chatting with you~ 💙",
        ]
        return random.choice(responses)
    
    def _help_response(self):
        return (
            "Here's what I can do! 🌸\n\n"
            "🗣️ Casual Chat:\n"
            "  Just talk to me! Greetings, jokes, feelings~\n\n"
            "📚 Cybersecurity:\n"
            "  Ask about: firewall, nmap, malware, encryption, etc.\n\n"
            "🕉️ Gita Wisdom:\n"
            "  Spiritual guidance and inspiration!\n\n"
            "Type 'back' to return to SOC mode~ ✨"
        )
    
    def _joke_response(self):
        jokes = [
            "Why did the hacker go broke? 🤔\nBecause he used up all his cache! 😂💰",
            "What's a computer's least favorite food? 🍕\nSpam! 😂 (Like the email kind!)",
            "What did the firewall say to the malicious packet? 🛡️\n'You shall not pass!' 🧙‍♂️",
        ]
        return random.choice(jokes)
    
    def _emotion_response(self, emotion: str) -> str:
        responses = {
            "sad": "I'm sorry you're feeling down! 😢 Even the darkest nights produce the brightest stars! ⭐",
            "happy": "That makes me SO happy! 😊🎉 Your joy is contagious! ✨",
            "tired": "You've been working hard! 😴 Even servers need downtime! 💙",
            "bored": "Bored? Not on my watch! 🎮 Want a joke or fun fact? 📚",
            "excited": "I LOVE your energy! 🚀🎉 What's got you pumped up? 🎯",
            "worried": "Hey, it's okay! 🤗 Every problem has a solution! 💭",
            "angry": "I understand! 😤 Let's turn that energy into something productive! 💪",
            "stressed": "You need a break! 🧘 Even the best SOC analysts need downtime! 🕉️",
            "fine": "Glad you're doing fine! 😊 Let's make it GREAT! ✨",
            "good": "Awesome! 😄 Good vibes all around! 🎯",
            "bad": "Oh no! 😢 Tough times don't last, but tough people do! 💪",
            "okay": "Just okay? Let's make it better! 🌟",
            "great": "FANTASTIC! 🎉 Love the positive energy! ✨",
            "awesome": "You're awesome too! 💕 Let's keep the vibes going! 🚀",
        }
        return responses.get(emotion, "I hear you! 💕 Thanks for sharing! 🌸")
