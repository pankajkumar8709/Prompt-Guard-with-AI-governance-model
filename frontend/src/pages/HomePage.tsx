import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import { Globe3D } from '../components/ui/Globe3D'

export function HomePage() {
  const navigate = useNavigate()

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#07080D]">
      <div className="grain-overlay" />
      
      {/* Globe Background */}
      <Globe3D />

      {/* Content */}
      <div className="relative z-10 flex flex-col items-center justify-center min-h-screen px-8">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          className="text-center max-w-5xl"
        >
          {/* Headline */}
          <h1 className="font-display font-extrabold mb-6" style={{ letterSpacing: '-0.04em' }}>
            <div className="text-white text-[96px] leading-none mb-4">
              PROMPT
            </div>
            <div className="gradient-text text-[96px] leading-none">
              GUARD
            </div>
          </h1>

          {/* Tagline */}
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.4, duration: 0.8 }}
            className="text-xl text-gray-400 font-light mb-12 max-w-2xl mx-auto"
            style={{ fontFamily: 'DM Sans' }}
          >
            Real-time threat detection powered by 3-layer AI security. 
            Block prompt injections, jailbreaks, and malicious attacks before they reach your LLM.
          </motion.p>

          {/* CTAs */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.6, duration: 0.8 }}
            className="flex items-center justify-center gap-4"
          >
            <motion.button
              onClick={() => navigate('/dashboard')}
              className="px-8 py-4 rounded-xl bg-cyan-500 text-black font-bold text-base hover-lift spring-transition"
              style={{ fontFamily: 'Syne', boxShadow: '0 20px 50px rgba(0,229,255,0.4)' }}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <span className="flex items-center gap-2">
                Open Dashboard
                <ArrowRight className="w-5 h-5" />
              </span>
            </motion.button>

            <motion.button
              onClick={() => navigate('/chat')}
              className="px-8 py-4 rounded-xl glass border border-[#252A3A] hover:border-violet-500 spring-transition"
              style={{ fontFamily: 'Syne', background: 'rgba(255,255,255,0.03)' }}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <span className="flex items-center gap-2 text-white font-bold text-base">
                Launch Chat
                <ArrowRight className="w-5 h-5" />
              </span>
            </motion.button>
          </motion.div>

          {/* Stats */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.8, duration: 0.8 }}
            className="mt-20 flex items-center justify-center gap-12"
          >
            <div className="text-center">
              <div className="text-4xl font-bold text-white mb-1 font-mono">99.9%</div>
              <div className="text-sm text-gray-500">Accuracy</div>
            </div>
            <div className="w-px h-12 bg-white/10" />
            <div className="text-center">
              <div className="text-4xl font-bold text-white mb-1 font-mono">&lt;200ms</div>
              <div className="text-sm text-gray-500">Latency</div>
            </div>
            <div className="w-px h-12 bg-white/10" />
            <div className="text-center">
              <div className="text-4xl font-bold text-white mb-1 font-mono">24/7</div>
              <div className="text-sm text-gray-500">Protection</div>
            </div>
          </motion.div>
        </motion.div>
      </div>
    </div>
  )
}
