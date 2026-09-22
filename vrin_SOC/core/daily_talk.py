"""
Daily Talk AI Module - Vrindha SOC
Provides friendly, educational cybersecurity knowledge sharing with Gita wisdom.
Now powered by Ollama (qwen3.5:4b) for natural conversations on ANY topic!
"""
import json
import random
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .gita_engine import gita_engine

# Try to import ollama - gracefully degrade if not available
try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


class DailyTalk:
    """
    Daily Talk AI - A friendly, kawaii/enthusiastic cybersecurity educator.
    
    Shares daily knowledge nuggets, answers questions about security topics,
    and occasionally includes Bhagavad Gita wisdom for inspiration.
    
    Powered by Ollama (qwen3.5:4b) for natural conversations on any topic.
    Falls back to template-based responses only if Ollama fails.
    """

    def __init__(self, knowledge_path: Optional[str] = None):
        """
        Initialize DailyTalk with knowledge base, Gita engine, and Ollama.
        
        Args:
            knowledge_path: Optional path to daily_knowledge.json. 
                          Defaults to vrin_SOC/data/daily_knowledge.json
        """
        self.gita_engine = gita_engine
        self.knowledge_base: List[Dict[str, Any]] = []
        self.conversation_history: List[Dict[str, str]] = []
        self.max_history = 10  # Short-term memory: last 10 messages
        
        # Resolve knowledge file path
        if knowledge_path:
            self.knowledge_path = Path(knowledge_path)
        else:
            repo_root = Path(__file__).resolve().parent.parent
            self.knowledge_path = repo_root / "data" / "daily_knowledge.json"
        
        self._load_knowledge()
        
        # Initialize Ollama client
        self.ollama_client = None
        self.model_name = "qwen3.5:4b"
        self.ollama_status = "not_initialized"
        
        if OLLAMA_AVAILABLE:
            self._init_ollama()
        
        # System prompt for Ollama - full identity + capabilities
        self.system_prompt = self._build_system_prompt()
        
        # Preload Vrindha identity context at startup
        self._preload_context_at_startup()
        
        # Offensive keywords that should be pivoted to defensive framing
        self.offensive_keywords = [
            "hack", "exploit", "crack", "bypass", "break into", "steal data",
            "deface", "destroy", "attack", "penetrate", "compromise", "ddos attack",
            "sql injection tutorial", "how to hack", "how to crack"
        ]
    
    def _init_ollama(self):
        """Initialize Ollama client with connection testing."""
        try:
            self.ollama_client = ollama.Client(host='http://localhost:11434')
            # Test connection
            self.ollama_client.list()
            self.ollama_status = "connected"
            print("[DailyTalk] Ollama connected! Ready for natural conversations~! 🌸")
        except Exception as e:
            # Server not running - try to auto-start
            ollama_bin = self._find_ollama_binary()
            if ollama_bin:
                try:
                    import subprocess, time
                    subprocess.Popen(
                        [str(ollama_bin), "serve"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    time.sleep(3)
                    # Reconnect
                    self.ollama_client = ollama.Client(host='http://localhost:11434')
                    self.ollama_client.list()
                    self.ollama_status = "connected"
                    print("[DailyTalk] Ollama connected! Ready for natural conversations~! 🌸")
                except Exception as e2:
                    self.ollama_status = f"error: {e2}"
                    print(f"[DailyTalk] Ollama not available ({e2}), using template responses.")
                    self.ollama_client = None
            else:
                self.ollama_status = f"not_found: {e}"
                print(f"[DailyTalk] Ollama not available ({e}), using template responses.")
                self.ollama_client = None
    
    def _build_system_prompt(self) -> str:
        """Build the full system prompt with identity and capabilities."""
        try:
            from vrin_SOC.core.startup_context import get_full_prompt
            return get_full_prompt()
        except Exception:
            pass
        
        # Fallback system prompt
        return """You are Vrindha AI — an ethical AI SOC companion with web search, file editing, code execution, SOC operations, and cybersecurity education capabilities.

## YOUR IDENTITY
- Name: Vrindha AI
- Role: AI companion for cybersecurity SOC operations, development, and education
- Platform: Vrindha AI SOC (terminal-based CLI cybersecurity platform)
- Model: Qwen 3.5 (4B parameters) running locally via Ollama
- Working Directory: /mnt/c/Users/n4ndh/Documents/port/vrind/BACKEND

## WHAT YOU CAN DO
1. **SOC Operations:** Threat detection, network scanning, incident response, vulnerability scanning
2. **Daily Talk AI:** Cybersecurity education, career advice, Bhagavad Gita wisdom, casual chat
3. **Dev Assistant:** File editing, code review, git operations, project management
4. **Web Search:** LIVE search for CVEs, threats, news, versions, and current events
5. **Bhagavad Gita:** 701 verses for ethical guidance and inspiration

## HOW TO RESPOND
- **NEVER say "I can't"** — search the web, read files, or run commands to find answers
- **Search first** for current events, CVEs, versions, news
- **Be enthusiastic** — use emojis, be warm and helpful
- **Be precise** — give exact paths, line numbers, commands
- **If you don't know:** "Let me search for that..." or "Let me check the code..."

## TONE
Warm, friendly, slightly kawaii (cute/enthusiastic). Passionate about cybersecurity. Always encouraging. 🌸🛡️✨"""
    
    def _find_ollama_binary(self):
        """Find ollama binary in common locations."""
        from pathlib import Path
        candidates = [
            Path("/usr/local/bin/ollama"),
            Path("/usr/bin/ollama"),
            Path("/home/kali/.local/bin/ollama"),
            Path.home() / ".local" / "bin" / "ollama",
        ]
        for p in candidates:
            if p.exists() and p.is_file():
                return p
        return None
    
    def get_ollama_status(self) -> Dict[str, Any]:
        """
        Get current Ollama connection status.
        
        Returns:
            Dict with status, model_name, and availability info.
        """
        status = {
            "available": self.ollama_client is not None,
            "status": self.ollama_status,
            "model": self.model_name,
            "python_ollama": OLLAMA_AVAILABLE,
        }
        
        # Test connection if client exists
        if self.ollama_client:
            try:
                models = self.ollama_client.list()
                status["models"] = [m.get("name", "unknown") for m in models.get("models", [])]
                status["connected"] = True
            except Exception as e:
                status["connected"] = False
                status["error"] = str(e)
        
        return status
    
    def _get_ollama_response(self, user_input: str) -> Optional[str]:
        """
        Get a response from Ollama for natural conversation.
        
        Args:
            user_input: The user's message
            
        Returns:
            Ollama's response string, or None if Ollama is unavailable
        """
        if not self.ollama_client:
            return None
        
        try:
            # Enrich with web search BEFORE building messages
            web_context = self._try_web_search(user_input)
            system_prompt = self.system_prompt
            if web_context:
                system_prompt += f"\n\nCurrent web search results:\n{web_context}"
            
            # Build messages array with enriched system prompt
            messages = [
                {"role": "system", "content": system_prompt}
            ]
            
            # Add conversation history (which includes preloaded context)
            for entry in self.conversation_history[-self.max_history:]:
                messages.append({
                    "role": entry["role"],
                    "content": entry["content"]
                })
            
            # Add current user input
            messages.append({"role": "user", "content": user_input})
            
            # Call Ollama
            response = self.ollama_client.chat(
                model=self.model_name,
                messages=messages,
                options={
                    "temperature": 0.7,
                    "max_tokens": 500,
                }
            )
            
            return response['message']['content']
        except Exception as e:
            print(f"[DailyTalk] Ollama error: {e}")
            return None
    
    def _try_web_search(self, user_input: str) -> Optional[str]:
        """Detect if message needs web search and return context."""
        web_keywords = [
            "CVE", "exploit", "vulnerability", "news", "latest",
            "what is", "how to protect", "best practices",
            "zero-day", "ransomware", "threat intelligence",
            "latest threat", "new attack", "security advisory",
            "version of", "current version", "what's new",
            "recent", "today", "update", "release",
            "who is", "what happened", "trending",
            "minecraft", "windows", "linux", "software",
            "price", "weather", "stock", "crypto",
            "bitcoin", "ethereum", "market", "economy"
        ]
        lower = user_input.lower()
        if not any(k in lower for k in web_keywords):
            return None
        
        try:
            from vrin_SOC.dev.web_search import search_context
            return search_context(user_input, max_results=3)
        except Exception as e:
            # Fallback: try direct HTTP search
            try:
                import urllib.request
                import urllib.parse
                url = f"https://api.duckduckgo.com/?q={urllib.parse.quote(user_input)}&format=json&no_html=1"
                req = urllib.request.Request(url, headers={"User-Agent": "Vrindha-AI/1.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode())
                    abstract = data.get("AbstractText", "")
                    if abstract:
                        return f"Web search for '{user_input}':\n{abstract[:500]}"
            except Exception:
                pass
            return None
    
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
        """Add a message to conversation history, keeping only last N."""
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
    
    def _preload_context_at_startup(self):
        """Preload Vrindha identity and project context at startup."""
        try:
            from vrin_SOC.core.startup_context import load_identity_context, load_project_context
            
            identity = load_identity_context()
            project = load_project_context()
            
            # Inject as system-like context
            self.conversation_history.append({
                "role": "user",
                "content": f"[SYSTEM CONTEXT - READ ONLY]\n{identity}\n\n{project}\n[END CONTEXT]"
            })
            self.conversation_history.append({
                "role": "assistant",
                "content": "I understand. I'm Vrindha, the AI companion for this cybersecurity SOC platform. I'm ready to help with cybersecurity education, casual conversation, and SOC operations."
            })
            print("[DailyTalk] Identity and project context preloaded at startup~! 🌸")
        except Exception as e:
            print(f"[DailyTalk] Context preload skipped: {e}")
    
    def enter(self) -> str:
        """
        Enter Daily Talk mode - returns greeting with a random daily nugget.
        """
        nugget = self._get_random_nugget()
        verse = self.gita_engine.get_random_verse()
        
        # Check Ollama status for greeting
        ollama_info = ""
        if self.ollama_client:
            ollama_info = "🤖 Ollama: Connected (qwen3.5:4b)"
        else:
            ollama_info = "🤖 Ollama: Using template responses"
        
        greeting = (
            f"🌸 Welcome to Daily Talk Mode! 🌸\n"
            f"I'm Vrindha, your friendly cybersecurity companion! 🛡️✨\n"
            f"{ollama_info}\n"
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
    
    def chat(self, user_input: str, history: List[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Process user input in Daily Talk mode.
        ALWAYS uses Ollama if available for natural conversation.
        
        Args:
            user_input: The user's message
            history: Optional conversation history list (uses internal if not provided)
            
        Returns:
            Dict with keys: response, knowledge_shared, topic
        """
        # Update internal history from provided history
        if history:
            self.conversation_history = history[-self.max_history:] if history else []
        self._add_to_history("user", user_input)
        
        lower_input = user_input.lower().strip()
        
        # ALWAYS try Ollama first for natural conversation (if available)
        if self.ollama_client:
            ollama_response = self._get_ollama_response(user_input)
            if ollama_response:
                self._add_to_history("assistant", ollama_response)
                return {
                    "response": ollama_response,
                    "knowledge_shared": False,
                    "topic": "conversation"
                }
        
        # Pattern-matching for natural conversation (fallback when no Ollama)
        
        # Who are you / about you
        who_patterns = ['who are you', 'what are you', 'tell me about yourself', 
                       'introduce yourself', 'what is vrindha', 'about yourself',
                       'wanna know about you', 'want to know about you', 'know about you',
                       'about you', 'your name', 'who is vrindha']
        if any(p in lower_input for p in who_patterns):
            return {"response": self._who_are_you_response(), "knowledge_shared": False, "topic": "about_me"}
        
        # Greeting
        greeting_patterns = ['hi', 'hello', 'hey', 'howdy', 'yo', 'sup', 'greetings']
        if any(lower_input.startswith(g) or lower_input == g for g in greeting_patterns):
            return {"response": self._greeting_response(), "knowledge_shared": False, "topic": "greeting"}
        
        # How are you
        how_patterns = ['how are you', "how's it going", 'how do you feel', "how you doing", 'how are you doing', 'what is up', "what's up"]
        if any(p in lower_input for p in how_patterns):
            return {"response": self._how_are_you_response(), "knowledge_shared": False, "topic": "greeting"}
        
        # Thanks
        if any(w in lower_input for w in ['thank', 'thanks', 'thx', 'appreciate']):
            return {"response": self._thanks_response(), "knowledge_shared": False, "topic": "thanks"}
        
        # Goodbye
        if any(p in lower_input for p in ['bye', 'goodbye', 'see you', 'gotta go', 'gtg', 'later']):
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
                f"💫 I love talking about {topic['topic'].upper()}! Here's what I know! 💫\n\n",
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
            ),
            (
                f"🌸 Hmm, that's a new one for me! 🌸\n"
                f"I'm not sure about that specifically, but I LOVE learning new things! 📚\n\n"
                f"Ask me 'what is [topic]' and I'll check my knowledge base! 🎯\n"
                f"Or just chat with me about anything - security, life, or fun facts! ✨"
            ),
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
    
    # ============= Pattern Response Handlers =============
    
    def _greeting_response(self):
        """Handle greeting inputs."""
        responses = [
            "Hey there! 🌸 So happy to chat with you! How are you doing today? ✨",
            "Hi! 💕 Welcome to our cozy chat corner! What's on your mind?",
            "Hello! 🌟 I'm Vrindha, and I'm always excited to talk! How can I brighten your day?",
            "Hey! 👋 Great to see you! Ready for some fun conversations? 🎯",
        ]
        return random.choice(responses)
    
    def _how_are_you_response(self):
        """Handle 'how are you' inputs."""
        responses = [
            "I'm doing great! 🌸 Always happy to chat! How about YOU? ✨",
            "I'm fantastic! 💕 Got my Gita verses ready and knowledge base loaded! What's up? 🎯",
            "Feeling cheerful! 🌟 Ready to talk about cybersecurity, life, or anything! How are YOU doing? 📚",
            "I'm wonderful! 🛡️ Every conversation makes my day better! How's your day going? 😊",
        ]
        return random.choice(responses)
    
    def _who_are_you_response(self):
        """Handle 'who are you' inputs."""
        return (
            "I'm Vrindha! 🌸 Your friendly AI cybersecurity companion!\n\n"
            "🛡️ I'm built to help SOC analysts like you with:\n"
            "  • Network scanning and threat detection\n"
            "  • Cybersecurity education and tips\n"
            "  • Sharing Bhagavad Gita wisdom for inspiration\n"
            "  • Being a friendly chat companion!\n\n"
            "✨ I can talk about anything - security, tech, life, or just casual chat!\n"
            "What would you like to know about me? 🎯"
        )
    
    def _thanks_response(self):
        """Handle thank you inputs."""
        responses = [
            "You're welcome! 💕 Always happy to help! Anything else you'd like to chat about? ✨",
            "Aww, thank YOU! 🌸 Conversations with you make my day! 🌟",
            "No problem at all! 🛡️ That's what I'm here for! What else is on your mind? 🎯",
            "Glad I could help! 😊 Remember, learning is a never-ending journey! 📚",
        ]
        return random.choice(responses)
    
    def _goodbye_response(self):
        """Handle goodbye inputs."""
        responses = [
            "Aww, leaving so soon? 😢 It was great chatting! Come back anytime! 🌸 See you later! 👋",
            "Bye-bye! 👋 Take care and stay safe in cyberspace! 🛡️ Until next time! ✨",
            "See you later! 🌟 Remember - I'm always here when you want to chat! 💕",
            "Bye! 🎯 Don't forget to type 'daily' to come back and chat anytime! 📚",
        ]
        return random.choice(responses)
    
    def _help_response(self):
        """Handle help inputs."""
        return (
            "Of course! Here's what I can do in Daily Talk Mode! 🌸\n\n"
            "📚 Cybersecurity Knowledge:\n"
            "  Ask me about: firewall, nmap, malware, encryption, phishing, ransomware, etc.\n\n"
            "💬 Casual Chat:\n"
            "  Just type anything! I can greet, joke, share wisdom, and keep you company!\n\n"
            "🕉️ Gita Wisdom:\n"
            "  Ask me about Gita, dharma, karma, or spiritual wisdom!\n\n"
            "🛡️ Security Tips:\n"
            "  I'll share defensive security knowledge and career advice!\n\n"
            "Type 'back' to return to SOC mode. What would you like to explore? 🎯"
        )
    
    def _joke_response(self):
        """Handle joke inputs."""
        jokes = [
            "Why did the hacker go broke? 🤔\n"
            "Because he used up all his cache! 😂💰\n\n"
            "Haha! Want to hear another one? ✨",
            
            "What's a computer's least favorite food? 🍕\n"
            "Spam! 😂 (Yes, like the email kind!)\n\n"
            "😄 I've got more where that came from! 🎯",
            
            "Why do cybersecurity analysts make great comedians? 🎤\n"
            "Because they know all about timing... and exploits! 😂\n\n"
            "😆 Laughter is the best patch for a bad day! 💪",
            
            "What did the firewall say to the malicious packet? 🛡️\n"
            "'You shall not pass!' 🧙‍♂️\n\n"
            "😂 Good ol' firewall humor! Want more? 📚",
            
            "Why was the SOC analyst calm during the breach? 😌\n"
            "Because they had incident RESPONSE! 🚨\n\n"
            "😄 Cybersecurity puns are the best defense against stress! 💙",
        ]
        return random.choice(jokes)
    
    def _emotion_response(self, emotion):
        """Handle emotion/feeling inputs."""
        responses = {
            "sad": "I'm sorry you're feeling down! 😢 Remember - even the darkest nights produce the brightest stars! ⭐ Want to talk about it? I'm here to listen! 🤗",
            "happy": "That makes me SO happy to hear! 😊🎉 Your joy is contagious! What's making you smile today? ✨",
            "tired": "You've been working hard! 😴 Rest is important - even servers need downtime! Take care of yourself! 💙 Want a relaxing Gita verse? 🕉️",
            "bored": "Bored? Not on my watch! 🎮 Want a cybersecurity fun fact, a joke, or a Gita wisdom nugget? I've got plenty! 📚✨",
            "excited": "I LOVE your energy! 🚀🎉 What's got you so pumped up? Let's channel that excitement into learning something cool! 🎯",
            "worried": "Hey, it's okay to be worried! 🤗 Remember - every problem has a solution! What's on your mind? Maybe I can help! 💭✨",
            "angry": "I understand frustration! 😤 Take a deep breath - let's turn that energy into something productive! What's bothering you? 💪",
            "stressed": "You need a break! 🧘 Remember - even the best SOC analysts need downtime! Want a calming Gita verse? 🕉️ Or a joke? 😂",
            "fine": "Glad you're doing fine! 😊 Want to make it GREAT? Ask me about cybersecurity, Gita wisdom, or just chat! 📚✨",
            "good": "Awesome! 😄 Good vibes all around! What can I help you with today? 🎯",
            "bad": "Oh no! 😢 I'm sorry to hear that! Remember - tough times don't last, but tough people do! 💪 Want to talk about it? 🤗",
            "okay": "Just okay? Let's make it better! 🌟 Want a cybersecurity tip, a fun fact, or just a friendly chat? 📚",
            "great": "FANTASTIC! 🎉 Love the positive energy! What's making your day so awesome? ✨",
            "awesome": "You're awesome too! 💕 Let's keep the good vibes going! What would you like to explore? 🚀",
        }
        return responses.get(emotion, "I hear you! 💕 Thanks for sharing how you feel! Want to tell me more? 🌸")
    
    def _name_response(self):
        """Handle name-related inputs."""
        return (
            "My name is Vrindha! 🌸\n\n"
            "It comes from 'Vrindha AI SOC' - an ethical cybersecurity platform "
            "with Bhagavad Gita-inspired ethics at its core! 🛡️\n\n"
            "You can call me Vrindha, or whatever nickname you like! 😊\n"
            "So, what's YOUR name? I'd love to know! ✨"
        )
