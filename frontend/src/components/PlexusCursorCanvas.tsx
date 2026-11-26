import React, { useEffect, useRef } from 'react';

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  baseAlpha: number;
  color: string;
}

export const PlexusCursorCanvas: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return;

    let animFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    // Mouse coordinates & state
    let mouseX = -9999;
    let mouseY = -9999;
    let targetMouseX = -9999;
    let targetMouseY = -9999;
    let isMouseOnScreen = false;
    let isHoveringInteractive = false;

    const colorPalette = [
      'rgba(255, 255, 255,',
      'rgba(229, 231, 235,',
      'rgba(161, 161, 170,',
      'rgba(255, 77, 45,',
    ];

    // Compute particle count based on screen area (capped for optimal 60-120fps)
    const computeParticleCount = () => {
      const area = window.innerWidth * window.innerHeight;
      return Math.min(85, Math.max(35, Math.floor(area / 18000)));
    };

    let particles: Particle[] = [];

    const initParticles = () => {
      const count = computeParticleCount();
      particles = [];
      for (let i = 0; i < count; i++) {
        const colorPrefix = colorPalette[Math.floor(Math.random() * colorPalette.length)];
        particles.push({
          x: Math.random() * width,
          y: Math.random() * height,
          vx: (Math.random() - 0.5) * 0.45,
          vy: (Math.random() - 0.5) * 0.45,
          radius: Math.random() * 1.5 + 1.2,
          baseAlpha: Math.random() * 0.4 + 0.35,
          color: colorPrefix,
        });
      }
    };

    // Handle high DPI displays
    const handleResize = () => {
      if (!canvas) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      initParticles();
    };

    handleResize();

    // Mouse tracking with passive listener
    const handleMouseMove = (e: MouseEvent) => {
      targetMouseX = e.clientX;
      targetMouseY = e.clientY;
      if (!isMouseOnScreen) {
        mouseX = targetMouseX;
        mouseY = targetMouseY;
        isMouseOnScreen = true;
      }

      // Check if hovering an interactive element (button, link, input)
      const target = e.target as HTMLElement | null;
      if (target && (target.closest('button') || target.closest('a') || target.closest('input') || target.closest('[role="button"]'))) {
        isHoveringInteractive = true;
      } else {
        isHoveringInteractive = false;
      }
    };

    const handleMouseLeave = () => {
      isMouseOnScreen = false;
      targetMouseX = -9999;
      targetMouseY = -9999;
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    document.addEventListener('mouseleave', handleMouseLeave);
    window.addEventListener('resize', handleResize, { passive: true });

    // Distance thresholds
    const maxNodeDist = 110;
    const maxCursorDist = 170;

    // Render loop
    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // Smooth lerp mouse ring toward real mouse
      if (isMouseOnScreen) {
        mouseX += (targetMouseX - mouseX) * 0.22;
        mouseY += (targetMouseY - mouseY) * 0.22;
      }

      // 1. Update and draw particles
      const pLen = particles.length;
      for (let i = 0; i < pLen; i++) {
        const p = particles[i];

        // Move particle
        p.x += p.vx;
        p.y += p.vy;

        // Bounce gently off boundaries
        if (p.x < 0) {
          p.x = 0;
          p.vx *= -1;
        } else if (p.x > width) {
          p.x = width;
          p.vx *= -1;
        }

        if (p.y < 0) {
          p.y = 0;
          p.vy *= -1;
        } else if (p.y > height) {
          p.y = height;
          p.vy *= -1;
        }

        // Mouse interaction: slight elastic push away if too close
        if (isMouseOnScreen) {
          const dxM = p.x - targetMouseX;
          const dyM = p.y - targetMouseY;
          const distM = Math.sqrt(dxM * dxM + dyM * dyM);

          if (distM < 80 && distM > 0) {
            const force = (80 - distM) / 80;
            p.x += (dxM / distM) * force * 1.8;
            p.y += (dyM / distM) * force * 1.8;
          }
        }

        // Draw particle dot
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = `${p.color} ${p.baseAlpha})`;
        ctx.fill();

        // 2. Connect to nearby particles
        for (let j = i + 1; j < pLen; j++) {
          const p2 = particles[j];
          const dx = p.x - p2.x;
          const dy = p.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < maxNodeDist) {
            const alpha = (1 - dist / maxNodeDist) * 0.20;
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = `rgba(129, 140, 248, ${alpha})`;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }

        // 3. Connect to cursor if within range
        if (isMouseOnScreen) {
          const dxCursor = p.x - mouseX;
          const dyCursor = p.y - mouseY;
          const distCursor = Math.sqrt(dxCursor * dxCursor + dyCursor * dyCursor);

          if (distCursor < maxCursorDist) {
            const factor = 1 - distCursor / maxCursorDist;
            const lineAlpha = factor * 0.65;
            
            // Dynamic energetic beam connecting cursor to node
            ctx.beginPath();
            ctx.moveTo(mouseX, mouseY);
            ctx.lineTo(p.x, p.y);
            ctx.strokeStyle = `rgba(168, 85, 247, ${lineAlpha})`;
            ctx.lineWidth = 1 + factor * 0.6;
            ctx.stroke();

            // Highlight the connected particle with a subtle glow
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.radius + factor * 1.8, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(255, 255, 255, ${factor * 0.5})`;
            ctx.fill();
          }
        }
      }

      // 4. Render sleek modern cursor reticle & glow
      if (isMouseOnScreen && mouseX > 0 && mouseY > 0) {
        const ringRadius = isHoveringInteractive ? 20 : 13;
        const coreRadius = isHoveringInteractive ? 4 : 2.5;

        const gradient = ctx.createRadialGradient(mouseX, mouseY, 0, mouseX, mouseY, 60);
        gradient.addColorStop(0, isHoveringInteractive ? 'rgba(255, 77, 45, 0.18)' : 'rgba(255, 255, 255, 0.10)');
        gradient.addColorStop(0.5, 'rgba(255, 255, 255, 0.03)');
        gradient.addColorStop(1, 'transparent');

        ctx.beginPath();
        ctx.arc(mouseX, mouseY, 60, 0, Math.PI * 2);
        ctx.fillStyle = gradient;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(mouseX, mouseY, ringRadius, 0, Math.PI * 2);
        ctx.strokeStyle = isHoveringInteractive ? 'rgba(255, 77, 45, 0.75)' : 'rgba(255, 255, 255, 0.35)';
        ctx.lineWidth = 1.2;
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(targetMouseX, targetMouseY, coreRadius, 0, Math.PI * 2);
        ctx.fillStyle = isHoveringInteractive ? '#FF4D2D' : '#FFFFFF';
        ctx.fill();
      }

      animFrameId = requestAnimationFrame(render);
    };

    animFrameId = requestAnimationFrame(render);

    // Pause rendering when tab is hidden to save 100% CPU/GPU
    const handleVisibilityChange = () => {
      if (document.hidden) {
        cancelAnimationFrame(animFrameId);
      } else {
        animFrameId = requestAnimationFrame(render);
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseleave', handleMouseLeave);
      window.removeEventListener('resize', handleResize);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      cancelAnimationFrame(animFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="pointer-events-none fixed inset-0 z-20 w-full h-full"
      style={{ willChange: 'transform' }}
    />
  );
};
