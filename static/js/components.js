/**
 * MITRE-CORE UI Component Library
 * Comprehensive React-like component system for vanilla JS
 */

class MCUI {
  constructor() {
    this.components = new Map();
    this.init();
  }

  init() {
    this.setupEventListeners();
    this.setupAnimations();
  }

  // ============================================
  // COMPONENT FACTORIES
  // ============================================

  /**
   * Create a stat card component
   */
  static createStatCard({ value, label, trend, trendUp, icon, color = 'primary' }) {
    const colors = {
      primary: 'text-blue-400',
      success: 'text-emerald-400',
      warning: 'text-amber-400',
      danger: 'text-red-400',
      cyan: 'text-cyan-400'
    };

    const trendHtml = trend ? `
      <span class="flex items-center gap-1 text-xs ${trendUp ? 'text-emerald-400' : 'text-red-400'}">
        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                d="${trendUp ? 'M5 10l7-7m0 0l7 7m-7-7v18' : 'M19 14l-7 7m0 0l-7-7m7 7V3'}"/>
        </svg>
        ${trend}%
      </span>
    ` : '';

    return `
      <div class="card-glass p-5 group hover:border-blue-500/30 transition-all duration-300 cursor-default">
        <div class="flex items-start justify-between mb-3">
          <div class="p-2 rounded-lg bg-slate-800/50 ${colors[color]}">
            ${icon}
          </div>
          ${trendHtml}
        </div>
        <p class="text-2xl font-bold text-white mb-1">${value}</p>
        <p class="text-xs text-slate-400 uppercase tracking-wider">${label}</p>
      </div>
    `;
  }

  /**
   * Create a threat level badge
   */
  static createThreatBadge(level, count) {
    const configs = {
      critical: { class: 'badge-critical', label: 'Critical' },
      high: { class: 'badge-high', label: 'High' },
      medium: { class: 'badge-medium', label: 'Medium' },
      low: { class: 'badge-low', label: 'Low' }
    };
    
    const config = configs[level] || configs.medium;
    return `
      <div class="flex items-center justify-between p-3 rounded-lg bg-slate-800/50 border border-slate-700">
        <span class="badge ${config.class}">${config.label}</span>
        <span class="text-lg font-bold text-white">${count}</span>
      </div>
    `;
  }

  /**
   * Create a cluster card for attack visualization
   */
  static createClusterCard(cluster) {
    const stageColors = {
      'Initial Access': 'from-blue-500 to-cyan-400',
      'Execution': 'from-purple-500 to-pink-400',
      'Persistence': 'from-amber-500 to-orange-400',
      'Privilege Escalation': 'from-red-500 to-rose-400',
      'Defense Evasion': 'from-emerald-500 to-teal-400',
      'Credential Access': 'from-yellow-500 to-amber-400',
      'Discovery': 'from-indigo-500 to-purple-400',
      'Lateral Movement': 'from-orange-500 to-red-400',
      'Collection': 'from-cyan-500 to-blue-400',
      'Command and Control': 'from-violet-500 to-purple-400',
      'Exfiltration': 'from-pink-500 to-rose-400',
      'Impact': 'from-red-600 to-red-500'
    };

    const gradient = stageColors[cluster.stage] || 'from-slate-500 to-slate-400';
    const tactics = cluster.tactics || [];
    const attackTypes = cluster.attack_types || [];

    return `
      <div class="card-glass p-5 group cursor-pointer hover:border-blue-500/40 transition-all duration-300"
           onclick="showClusterDetails(${cluster.cluster_id})">
        <div class="flex items-start justify-between mb-4">
          <div class="flex items-center gap-3">
            <div class="w-12 h-12 rounded-xl bg-gradient-to-br ${gradient} flex items-center justify-center text-white font-bold text-lg shadow-lg">
              ${cluster.cluster_id}
            </div>
            <div>
              <h3 class="text-white font-semibold">Cluster ${cluster.cluster_id}</h3>
              <p class="text-xs text-slate-400">${cluster.size} events</p>
            </div>
          </div>
          <span class="text-xs font-medium px-2 py-1 rounded-full bg-slate-800 text-slate-300">
            ${cluster.stage || 'Unknown'}
          </span>
        </div>
        
        <div class="space-y-3">
          <div class="flex flex-wrap gap-2">
            ${tactics.slice(0, 3).map(t => `
              <span class="text-xs px-2 py-1 rounded-md bg-slate-800/70 text-slate-300">${t}</span>
            `).join('')}
          </div>
          
          ${cluster.avg_correlation ? `
            <div class="flex items-center gap-2">
              <div class="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div class="h-full bg-gradient-to-r from-blue-500 to-cyan-400 rounded-full" 
                     style="width: ${(cluster.avg_correlation * 100).toFixed(0)}%"></div>
              </div>
              <span class="text-xs text-slate-400">${(cluster.avg_correlation * 100).toFixed(0)}%</span>
            </div>
          ` : ''}
          
          <div class="text-xs text-slate-500">
            ${attackTypes.slice(0, 2).join(' • ')}
          </div>
        </div>
        
        <div class="mt-4 pt-3 border-t border-slate-700/50 flex items-center gap-4 text-xs text-slate-400">
          <span class="flex items-center gap-1">
            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                    d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            ${cluster.start_date ? new Date(cluster.start_date).toLocaleDateString() : 'N/A'}
          </span>
          <span class="flex items-center gap-1">
            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                    d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/>
            </svg>
            ${cluster.size} events
          </span>
        </div>
      </div>
    `;
  }

  /**
   * Create an alert/notification item
   */
  static createAlertItem(alert) {
    const severityColors = {
      critical: 'border-l-red-500 bg-red-500/5',
      high: 'border-l-orange-500 bg-orange-500/5',
      medium: 'border-l-amber-500 bg-amber-500/5',
      low: 'border-l-blue-500 bg-blue-500/5'
    };

    return `
      <div class="p-4 border-l-4 ${severityColors[alert.severity] || severityColors.medium} 
                  rounded-r-lg mb-2 animate-slide-up">
        <div class="flex items-start justify-between">
          <div>
            <h4 class="text-sm font-semibold text-white mb-1">${alert.title}</h4>
            <p class="text-xs text-slate-400">${alert.description}</p>
          </div>
          <span class="text-xs text-slate-500">${alert.time}</span>
        </div>
      </div>
    `;
  }

  /**
   * Create a connector status card
   */
  static createConnectorCard(connector) {
    const statusColors = {
      connected: 'bg-emerald-500',
      disconnected: 'bg-red-500',
      connecting: 'bg-amber-500 animate-pulse',
      error: 'bg-red-600'
    };

    return `
      <div class="card-glass p-4 flex items-center justify-between group">
        <div class="flex items-center gap-3">
          <div class="w-2 h-2 rounded-full ${statusColors[connector.status] || statusColors.disconnected}"></div>
          <div>
            <h4 class="text-sm font-medium text-white">${connector.id}</h4>
            <p class="text-xs text-slate-400">${connector.type}</p>
          </div>
        </div>
        <div class="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
          <button onclick="testConnector('${connector.id}')" 
                  class="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-white"
                  title="Test connection">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4"/>
            </svg>
          </button>
          <button onclick="removeConnector('${connector.id}')" 
                  class="p-1.5 rounded-lg hover:bg-red-500/20 text-slate-400 hover:text-red-400"
                  title="Remove">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>
      </div>
    `;
  }

  // ============================================
  // ANIMATION UTILITIES
  // ============================================

  static animateCounter(element, target, duration = 1000) {
    const start = 0;
    const startTime = performance.now();

    const update = (currentTime) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const easeOutQuart = 1 - Math.pow(1 - progress, 4);
      const current = Math.floor(start + (target - start) * easeOutQuart);
      
      element.textContent = current.toLocaleString();
      
      if (progress < 1) {
        requestAnimationFrame(update);
      }
    };

    requestAnimationFrame(update);
  }

  static staggerAnimation(elements, delay = 50) {
    elements.forEach((el, i) => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(10px)';
      setTimeout(() => {
        el.style.transition = 'all 0.3s ease';
        el.style.opacity = '1';
        el.style.transform = 'translateY(0)';
      }, i * delay);
    });
  }

  // ============================================
  // LOADING STATES
  // ============================================

  static showLoading(container, type = 'spinner') {
    const loaders = {
      spinner: `
        <div class="flex items-center justify-center p-8">
          <div class="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin"></div>
        </div>
      `,
      skeleton: `
        <div class="space-y-3 p-4">
          <div class="skeleton h-4 w-3/4"></div>
          <div class="skeleton h-4 w-1/2"></div>
          <div class="skeleton h-4 w-2/3"></div>
        </div>
      `,
      pulse: `
        <div class="flex items-center justify-center p-8">
          <div class="flex items-center gap-2">
            <div class="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
            <div class="w-2 h-2 bg-blue-500 rounded-full animate-pulse" style="animation-delay: 0.2s"></div>
            <div class="w-2 h-2 bg-blue-500 rounded-full animate-pulse" style="animation-delay: 0.4s"></div>
          </div>
        </div>
      `
    };

    container.innerHTML = loaders[type] || loaders.spinner;
  }

  // ============================================
  // TOAST NOTIFICATIONS
  // ============================================

  static showToast({ message, type = 'info', duration = 3000 }) {
    const colors = {
      success: 'bg-emerald-500/90 border-emerald-400/30',
      error: 'bg-red-500/90 border-red-400/30',
      warning: 'bg-amber-500/90 border-amber-400/30',
      info: 'bg-blue-500/90 border-blue-400/30'
    };

    const icons = {
      success: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>',
      error: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>',
      warning: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>',
      info: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'
    };

    const toast = document.createElement('div');
    toast.className = `fixed bottom-4 right-4 z-50 flex items-center gap-3 px-4 py-3 rounded-xl 
                      ${colors[type]} backdrop-blur-sm border text-white shadow-lg animate-slide-up`;
    toast.innerHTML = `
      ${icons[type]}
      <span class="text-sm font-medium">${message}</span>
    `;

    document.body.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  // ============================================
  // MODAL SYSTEM
  // ============================================

  static showModal({ title, content, onClose, actions = [] }) {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center p-4';
    modal.innerHTML = `
      <div class="absolute inset-0 bg-slate-900/80 backdrop-blur-sm" onclick="this.closest('.fixed').remove()"></div>
      <div class="relative w-full max-w-lg card-glass p-6 animate-scale-in">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-lg font-semibold text-white">${title}</h3>
          <button onclick="this.closest('.fixed').remove()" class="text-slate-400 hover:text-white">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>
        <div class="text-slate-300">${content}</div>
        ${actions.length ? `
          <div class="flex justify-end gap-2 mt-6">
            ${actions.map(a => `
              <button onclick="${a.onClick || 'this.closest(\'.fixed\').remove()'})" 
                      class="${a.class || 'btn btn-secondary'}">
                ${a.label}
              </button>
            `).join('')}
          </div>
        ` : ''}
      </div>
    `;

    document.body.appendChild(modal);
    return modal;
  }

  // ============================================
  // CHART/GRAPH HELPERS
  // ============================================

  static createMiniChart(data, options = {}) {
    const { width = 100, height = 30, color = '#3b82f6', fill = true } = options;
    const max = Math.max(...data);
    const min = Math.min(...data);
    const range = max - min || 1;
    
    const points = data.map((val, i) => {
      const x = (i / (data.length - 1)) * width;
      const y = height - ((val - min) / range) * height;
      return `${x},${y}`;
    }).join(' ');

    return `
      <svg width="${width}" height="${height}" class="overflow-visible">
        ${fill ? `
          <defs>
            <linearGradient id="chartGradient" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" style="stop-color:${color};stop-opacity:0.3" />
              <stop offset="100%" style="stop-color:${color};stop-opacity:0" />
            </linearGradient>
          </defs>
          <polygon points="0,${height} ${points} ${width},${height}" 
                   fill="url(#chartGradient)" />
        ` : ''}
        <polyline points="${points}" fill="none" stroke="${color}" stroke-width="2" 
                  stroke-linecap="round" stroke-linejoin="round" />
      </svg>
    `;
  }

  // ============================================
  // EVENT HANDLERS
  // ============================================

  setupEventListeners() {
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.ctrlKey || e.metaKey) {
        switch(e.key) {
          case 'u':
            e.preventDefault();
            document.getElementById('file-input')?.click();
            break;
          case 'd':
            e.preventDefault();
            this.toggleDevMode();
            break;
          case 'r':
            e.preventDefault();
            window.location.reload();
            break;
        }
      }
    });

    // Handle visibility change for performance
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        document.body.classList.add('paused');
      } else {
        document.body.classList.remove('paused');
      }
    });
  }

  setupAnimations() {
    // Intersection Observer for scroll animations
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('animate-fade-in');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });

    document.querySelectorAll('.animate-on-scroll').forEach(el => {
      observer.observe(el);
    });
  }

  // ============================================
  // UTILITY FUNCTIONS
  // ============================================

  static formatNumber(num) {
    if (num >= 1e6) return (num / 1e6).toFixed(1) + 'M';
    if (num >= 1e3) return (num / 1e3).toFixed(1) + 'K';
    return num.toString();
  }

  static formatBytes(bytes) {
    const sizes = ['B', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + sizes[i];
  }

  static timeAgo(date) {
    const seconds = Math.floor((new Date() - new Date(date)) / 1000);
    const intervals = {
      year: 31536000,
      month: 2592000,
      week: 604800,
      day: 86400,
      hour: 3600,
      minute: 60,
      second: 1
    };

    for (const [unit, secondsInUnit] of Object.entries(intervals)) {
      const interval = Math.floor(seconds / secondsInUnit);
      if (interval >= 1) {
        return `${interval} ${unit}${interval > 1 ? 's' : ''} ago`;
      }
    }
    return 'Just now';
  }

  static debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  static throttle(func, limit) {
    let inThrottle;
    return function(...args) {
      if (!inThrottle) {
        func.apply(this, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  }
}

// Initialize global UI instance
window.MCUI = MCUI;
const mcui = new MCUI();
