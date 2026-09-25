/**
 * PHISHGUARD AI // CYBERPUNK HUD CANVAS MATRIX & TELEMETRY GRID
 */

export class CyberCanvas {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.particles = [];
    this.scanLineY = 0;
    this.scanDirection = 1;
    this.width = 0;
    this.height = 0;
    this.animId = null;

    this.init();
  }

  init() {
    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.createParticles(45);
    this.render();
  }

  resize() {
    if (!this.canvas) return;
    this.width = this.canvas.width = window.innerWidth;
    this.height = this.canvas.height = window.innerHeight;
  }

  createParticles(count) {
    this.particles = [];
    for (let i = 0; i < count; i++) {
      this.particles.push({
        x: Math.random() * this.width,
        y: Math.random() * this.height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        size: Math.random() * 2 + 1,
        color: Math.random() > 0.8 ? '#00e5ff' : '#00ff88',
        alpha: Math.random() * 0.5 + 0.2
      });
    }
  }

  render() {
    if (!this.ctx) return;
    this.ctx.clearRect(0, 0, this.width, this.height);

    // 1. Draw subtle isometric / cyber perspective grid
    const gridSize = 48;
    this.ctx.strokeStyle = 'rgba(0, 255, 136, 0.035)';
    this.ctx.lineWidth = 1;

    // Vertical lines
    for (let x = 0; x < this.width; x += gridSize) {
      this.ctx.beginPath();
      this.ctx.moveTo(x, 0);
      this.ctx.lineTo(x, this.height);
      this.ctx.stroke();
    }

    // Horizontal lines
    for (let y = 0; y < this.height; y += gridSize) {
      this.ctx.beginPath();
      this.ctx.moveTo(0, y);
      this.ctx.lineTo(this.width, y);
      this.ctx.stroke();
    }

    // 2. Draw telemetry particles and inter-node connections
    const pLen = this.particles.length;
    for (let i = 0; i < pLen; i++) {
      const p = this.particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0) p.x = this.width;
      if (p.x > this.width) p.x = 0;
      if (p.y < 0) p.y = this.height;
      if (p.y > this.height) p.y = 0;

      // Draw particle
      this.ctx.fillStyle = p.color;
      this.ctx.globalAlpha = p.alpha;
      this.ctx.beginPath();
      this.ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      this.ctx.fill();

      // Connect nearby particles with cyber filaments
      for (let j = i + 1; j < pLen; j++) {
        const p2 = this.particles[j];
        const dx = p.x - p2.x;
        const dy = p.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 110) {
          this.ctx.strokeStyle = '#00ff88';
          this.ctx.globalAlpha = (1 - dist / 110) * 0.12;
          this.ctx.beginPath();
          this.ctx.moveTo(p.x, p.y);
          this.ctx.lineTo(p2.x, p2.y);
          this.ctx.stroke();
        }
      }
    }

    // 3. Subtle Cyber Sweep Beam
    this.scanLineY += 1.2 * this.scanDirection;
    if (this.scanLineY > this.height) this.scanLineY = 0;

    const grad = this.ctx.createLinearGradient(0, this.scanLineY - 30, 0, this.scanLineY + 30);
    grad.addColorStop(0, 'rgba(0, 229, 255, 0)');
    grad.addColorStop(0.5, 'rgba(0, 229, 255, 0.045)');
    grad.addColorStop(1, 'rgba(0, 229, 255, 0)');

    this.ctx.fillStyle = grad;
    this.ctx.globalAlpha = 1;
    this.ctx.fillRect(0, this.scanLineY - 30, this.width, 60);

    this.animId = requestAnimationFrame(() => this.render());
  }

  destroy() {
    if (this.animId) cancelAnimationFrame(this.animId);
  }
}
