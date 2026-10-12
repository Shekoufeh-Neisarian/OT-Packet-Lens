/**
 * Interactive Network Topology Canvas Engine.
 * Implements physics-based force layout for OT/IT asset nodes and communication links.
 */

class NetworkTopology {
  constructor(canvasId, onNodeClick) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.onNodeClick = onNodeClick;

    this.nodes = [];
    this.links = [];
    this.animId = null;
    this.simIteration = 0;
    this.draggedNode = null;
    this.hoveredNode = null;
    this.scale = 1.0;
    this.offsetX = 0;
    this.offsetY = 0;

    this.initCanvasSize();
    this.attachEvents();
  }

  initCanvasSize() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;
    const changed = this.canvas.width !== Math.round(rect.width) || this.canvas.height !== Math.round(rect.height);
    this.canvas.width = Math.round(rect.width);
    this.canvas.height = Math.round(rect.height);
    if (changed && this.nodes.length) {
      this.nodes.forEach((node, i) => {
        const angle = i / this.nodes.length * Math.PI * 2;
        node.x = this.canvas.width / 2 + Math.cos(angle) * this.canvas.width * 0.35;
        node.y = this.canvas.height / 2 + Math.sin(angle) * this.canvas.height * 0.32;
        node.vx = 0; node.vy = 0;
      });
      this.render();
      this.startSimulation();
    }
  }

  setData(graphData) {
    if (!graphData || !graphData.nodes) return;
    
    const w = this.canvas.width;
    const h = this.canvas.height;
    
    // Position nodes radially or randomly around center
    const total = graphData.nodes.length;
    this.nodes = graphData.nodes.map((n, i) => {
      const angle = (i / total) * 2 * Math.PI;
      const radius = Math.min(w, h) * 0.32;
      return {
        ...n,
        x: w / 2 + Math.cos(angle) * radius + (Math.random() - 0.5) * 40,
        y: h / 2 + Math.sin(angle) * radius + (Math.random() - 0.5) * 40,
        vx: 0,
        vy: 0,
        radius: n.is_ot ? 18 : 14
      };
    });

    const nodeMap = new Map();
    this.nodes.forEach(n => nodeMap.set(n.id, n));

    this.links = (graphData.links || []).map(l => {
      return {
        source: nodeMap.get(l.source),
        target: nodeMap.get(l.target),
        value: l.value,
        protocols: l.protocols
      };
    }).filter(l => l.source && l.target);

    this.startSimulation();
  }

  startSimulation() {
    // There is no permanent animation loop: stop when settled or after a finite budget.
    if (!this.canvas || !this.nodes.length) return;
    if (this.animId !== null) cancelAnimationFrame(this.animId);
    this.animId = null;
    this.simIteration = 0;
    let quietFrames = 0;
    const maxFrames = 360;
    const movementThreshold = 0.16;

    const tick = () => {
      this.animId = null;
      if (!this.canvas.isConnected) return;
      if (!this.canvas.offsetParent) { this.render(); return; }
      const movement = this.updateForces();
      this.render();
      this.simIteration++;
      quietFrames = movement < movementThreshold ? quietFrames + 1 : 0;
      // A drag uses direct pointer rendering and restarts the simulation on release.
      if (this.draggedNode || quietFrames >= 18 || this.simIteration >= maxFrames) return;
      this.animId = requestAnimationFrame(tick);
    };
    this.animId = requestAnimationFrame(tick);
  }

  updateForces() {
    if (!this.canvas.offsetParent) return;
    const w = this.canvas.width;
    const h = this.canvas.height;
    const kRepel = 6000;
    const kSpring = 0.04;
    const centerAttract = 0.001;

    // Repulsion between nodes
    for (let i = 0; i < this.nodes.length; i++) {
      const n1 = this.nodes[i];
      for (let j = i + 1; j < this.nodes.length; j++) {
        const n2 = this.nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const distSq = dx * dx + dy * dy + 100;
        const dist = Math.sqrt(distSq);
        const force = kRepel / distSq;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;

        if (n1 !== this.draggedNode) { n1.vx -= fx; n1.vy -= fy; }
        if (n2 !== this.draggedNode) { n2.vx += fx; n2.vy += fy; }
      }

      // Center attraction
      if (n1 !== this.draggedNode) {
        n1.vx += (w / 2 - n1.x) * centerAttract;
        n1.vy += (h / 2 - n1.y) * centerAttract;
      }
    }

    // Spring forces on links
    for (const link of this.links) {
      const s = link.source;
      const t = link.target;
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const targetDist = 200;
      const force = (dist - targetDist) * kSpring;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;

      if (s !== this.draggedNode) { s.vx += fx; s.vy += fy; }
      if (t !== this.draggedNode) { t.vx -= fx; t.vy -= fy; }
    }

    // Velocity damping and position updates
    let maxMovement = 0;
    for (const node of this.nodes) {
      if (node === this.draggedNode) continue;
      node.vx *= 0.85;
      node.vy *= 0.85;
      maxMovement = Math.max(maxMovement, Math.hypot(node.vx, node.vy));
      node.x += node.vx;
      node.y += node.vy;

      // Keep within bounds
      const pad = 30;
      node.x = Math.max(pad, Math.min(w - pad, node.x));
      node.y = Math.max(pad, Math.min(h - pad, node.y));
    }
    return maxMovement;
  }

  render() {
    const ctx = this.ctx;
    const w = this.canvas.width;
    const h = this.canvas.height;

    ctx.clearRect(0, 0, w, h);

    // Draw Links
    for (const link of this.links) {
      ctx.beginPath();
      ctx.moveTo(link.source.x, link.source.y);
      ctx.lineTo(link.target.x, link.target.y);
      ctx.strokeStyle = "rgba(148, 163, 184, 0.25)";
      ctx.lineWidth = Math.min(6, Math.max(1.5, Math.log10(link.value + 1)));
      ctx.stroke();

      // Protocol label on link if hovered
      if (this.hoveredNode && (this.hoveredNode === link.source || this.hoveredNode === link.target)) {
        ctx.strokeStyle = "rgba(6, 182, 212, 0.6)";
        ctx.stroke();
      }
    }

    // Draw Nodes
    for (const node of this.nodes) {
      const isHovered = (node === this.hoveredNode);
      const isDragged = (node === this.draggedNode);
      const r = node.radius + (isHovered ? 4 : 0);

      // Outer glow for OT Assets
      if (node.is_ot || isHovered) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, r + 6, 0, 2 * Math.PI);
        ctx.fillStyle = this.getRoleColor(node.role, 0.2);
        ctx.fill();
      }

      // Node Body
      ctx.beginPath();
      ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
      ctx.fillStyle = this.getRoleColor(node.role, 0.9);
      ctx.fill();
      ctx.lineWidth = 2;
      ctx.strokeStyle = "#ffffff";
      ctx.stroke();

      // Node Label
      ctx.font = `${isHovered ? "bold 12px" : "11px"} -apple-system, sans-serif`;
      ctx.fillStyle = isHovered ? "#ffffff" : "#cbd5e1";
      ctx.textAlign = "center";
      ctx.fillText(node.label || node.id, node.x, node.y + r + 16);

      // Role subtitle
      ctx.font = "9px -apple-system, sans-serif";
      ctx.fillStyle = "#94a3b8";
      ctx.fillText(node.role, node.x, node.y + r + 28);
    }
  }

  getRoleColor(role, alpha = 1) {
    const colors = {
      "PLC": `rgba(6, 182, 212, ${alpha})`,
      "HMI": `rgba(16, 185, 129, ${alpha})`,
      "Engineering Workstation": `rgba(245, 158, 11, ${alpha})`,
      "SCADA Server": `rgba(139, 92, 246, ${alpha})`,
      "Network Device": `rgba(59, 130, 246, ${alpha})`,
      "Server": `rgba(107, 114, 128, ${alpha})`,
      "Workstation": `rgba(56, 189, 248, ${alpha})`,
      "Unknown": `rgba(239, 68, 68, ${alpha})`
    };
    return colors[role] || `rgba(148, 163, 184, ${alpha})`;
  }

  attachEvents() {
    window.addEventListener('resize', () => this.initCanvasSize());

    this.canvas.addEventListener('mousedown', (e) => {
      const pos = this.getMousePos(e);
      const hit = this.findNodeAt(pos.x, pos.y);
      if (hit) {
        this.draggedNode = hit;
        if (this.animId !== null) cancelAnimationFrame(this.animId);
        this.animId = null;
        this.render();
      }
    });

    this.canvas.addEventListener('mousemove', (e) => {
      const pos = this.getMousePos(e);
      if (this.draggedNode) {
        this.draggedNode.x = pos.x;
        this.draggedNode.y = pos.y;
        this.render();
      } else {
        const hit = this.findNodeAt(pos.x, pos.y);
        if (this.hoveredNode !== hit) {
          this.hoveredNode = hit;
          this.render();
        }
        this.canvas.style.cursor = hit ? "pointer" : "default";
      }
    });

    window.addEventListener('mouseup', (e) => {
      if (this.draggedNode) {
        this.draggedNode = null;
        this.startSimulation();
      }
    });

    this.canvas.addEventListener('mouseleave', () => {
      if (!this.draggedNode && this.hoveredNode) {
        this.hoveredNode = null;
        this.render();
      }
    });

    this.canvas.addEventListener('click', (e) => {
      const pos = this.getMousePos(e);
      const hit = this.findNodeAt(pos.x, pos.y);
      if (hit && this.onNodeClick) {
        this.onNodeClick(hit.id);
      }
    });
  }

  getMousePos(e) {
    const rect = this.canvas.getBoundingClientRect();
    return {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    };
  }

  findNodeAt(x, y) {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      const dx = x - n.x;
      const dy = y - n.y;
      if (dx * dx + dy * dy <= (n.radius + 6) * (n.radius + 6)) {
        return n;
      }
    }
    return null;
  }
}
