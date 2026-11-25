import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import {
  Globe,
  Shield,
  Radio,
  Flame,
  Maximize2,
  Rotate3d,
  Layers,
  Activity,
  Zap,
  Info
} from 'lucide-react';
import { sound } from '../utils/audio';

interface ThreatVector {
  id: string;
  city: string;
  country: string;
  country_code: string;
  lat: number;
  lon: number;
  ip: string;
  attack_type: string;
  technique: string;
  severity: string;
  risk_score: number;
  bandwidth: string;
}

interface Enclave {
  name: string;
  city: string;
  country: string;
  lat: number;
  lon: number;
}

export const ThreatGlobeView: React.FC = () => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [threatData, setThreatData] = useState<{
    target_enclave: Enclave;
    active_vectors: ThreatVector[];
    global_threat_index: string;
    inbound_rate_eps: number;
  } | null>(null);
  const [selectedVector, setSelectedVector] = useState<ThreatVector | null>(null);
  const [autoRotate, setAutoRotate] = useState(true);

  useEffect(() => {
    fetchGeoThreats();
    const interval = setInterval(fetchGeoThreats, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchGeoThreats = async () => {
    try {
      const res = await fetch('/api/geo/threats');
      if (res.ok) {
        const data = await res.json();
        setThreatData(data);
        if (!selectedVector && data.active_vectors && data.active_vectors.length > 0) {
          setSelectedVector(data.active_vectors[0]);
        }
      }
    } catch (e) {
      console.error('Failed to load geo threats', e);
    }
  };

  // Convert (lat, lon) to 3D Sphere Vector
  const latLonToVector3 = (lat: number, lon: number, radius: number): THREE.Vector3 => {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lon + 180) * (Math.PI / 180);
    const x = -(radius * Math.sin(phi) * Math.cos(theta));
    const z = radius * Math.sin(phi) * Math.sin(theta);
    const y = radius * Math.cos(phi);
    return new THREE.Vector3(x, y, z);
  };

  useEffect(() => {
    if (!containerRef.current || !threatData) return;

    const container = containerRef.current;
    const width = container.clientWidth;
    const height = container.clientHeight || 520;

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 80, 260);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    const GLOBE_RADIUS = 80;
    const globeGroup = new THREE.Group();
    scene.add(globeGroup);

    // 2. Base Dark Sphere
    const sphereGeo = new THREE.SphereGeometry(GLOBE_RADIUS, 48, 48);
    const sphereMat = new THREE.MeshBasicMaterial({
      color: 0x090812,
      transparent: true,
      opacity: 0.94
    });
    const baseSphere = new THREE.Mesh(sphereGeo, sphereMat);
    globeGroup.add(baseSphere);

    // 3. Electric Violet Wireframe Grid
    const wireGeo = new THREE.SphereGeometry(GLOBE_RADIUS + 0.2, 32, 24);
    const wireMat = new THREE.MeshBasicMaterial({
      color: 0x6366F1,
      wireframe: true,
      transparent: true,
      opacity: 0.09
    });
    const wireMesh = new THREE.Mesh(wireGeo, wireMat);
    globeGroup.add(wireMesh);

    // 4. Dot Grid Constellation (Simulating Earth Landmass & Global Points)
    const pointsCount = 1400;
    const dotCoords = new Float32Array(pointsCount * 3);
    for (let i = 0; i < pointsCount; i++) {
      const phi = Math.acos(-1 + (2 * i) / pointsCount);
      const theta = Math.sqrt(pointsCount * Math.PI) * phi;
      const x = GLOBE_RADIUS * Math.cos(theta) * Math.sin(phi);
      const y = GLOBE_RADIUS * Math.sin(theta) * Math.sin(phi);
      const z = GLOBE_RADIUS * Math.cos(phi);
      dotCoords[i * 3] = x;
      dotCoords[i * 3 + 1] = y;
      dotCoords[i * 3 + 2] = z;
    }
    const dotGeo = new THREE.BufferGeometry();
    dotGeo.setAttribute('position', new THREE.BufferAttribute(dotCoords, 3));
    const dotMat = new THREE.PointsMaterial({
      color: 0x818CF8,
      size: 1.4,
      transparent: true,
      opacity: 0.35
    });
    const dotPoints = new THREE.Points(dotGeo, dotMat);
    globeGroup.add(dotPoints);

    // 5. Target Enclave Pin (San Francisco, AWS us-west-1)
    const enclavePos = latLonToVector3(
      threatData.target_enclave.lat,
      threatData.target_enclave.lon,
      GLOBE_RADIUS + 1
    );
    const enclavePinGeo = new THREE.SphereGeometry(2.5, 16, 16);
    const enclavePinMat = new THREE.MeshBasicMaterial({ color: 0x10B981 });
    const enclavePin = new THREE.Mesh(enclavePinGeo, enclavePinMat);
    enclavePin.position.copy(enclavePos);
    globeGroup.add(enclavePin);

    // Target Enclave Pulse Ring
    const ringGeo = new THREE.RingGeometry(2.8, 4.5, 32);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0x10B981,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.8
    });
    const enclaveRing = new THREE.Mesh(ringGeo, ringMat);
    enclaveRing.position.copy(enclavePos);
    enclaveRing.lookAt(new THREE.Vector3(0, 0, 0));
    globeGroup.add(enclaveRing);

    // 6. Threat Adversaries & Ballistic Trajectory Arcs
    const projectileMeshes: { mesh: THREE.Mesh; curve: THREE.QuadraticBezierCurve3; progress: number; speed: number }[] = [];

    threatData.active_vectors.forEach(adv => {
      const originPos = latLonToVector3(adv.lat, adv.lon, GLOBE_RADIUS + 1);

      // Node Marker
      const isCritical = adv.severity === 'CRITICAL';
      const nodeColor = isCritical ? 0xF43F5E : 0xF59E0B;
      const advGeo = new THREE.SphereGeometry(isCritical ? 2.2 : 1.6, 16, 16);
      const advMat = new THREE.MeshBasicMaterial({ color: nodeColor });
      const advMesh = new THREE.Mesh(advGeo, advMat);
      advMesh.position.copy(originPos);
      globeGroup.add(advMesh);

      // Ballistic 3D Curve
      const midPoint = new THREE.Vector3().addVectors(originPos, enclavePos).multiplyScalar(0.5);
      const distance = originPos.distanceTo(enclavePos);
      const elevation = GLOBE_RADIUS + distance * 0.45;
      midPoint.setLength(elevation);

      const curve = new THREE.QuadraticBezierCurve3(originPos, midPoint, enclavePos);
      const curvePoints = curve.getPoints(50);
      const curveGeo = new THREE.BufferGeometry().setFromPoints(curvePoints);
      const curveMat = new THREE.LineBasicMaterial({
        color: nodeColor,
        transparent: true,
        opacity: isCritical ? 0.6 : 0.35,
        linewidth: 1
      });
      const curveLine = new THREE.Line(curveGeo, curveMat);
      globeGroup.add(curveLine);

      // Animated Inbound Missile/Projectile Particle
      const projGeo = new THREE.SphereGeometry(1.4, 8, 8);
      const projMat = new THREE.MeshBasicMaterial({ color: 0xFFFFFF });
      const projMesh = new THREE.Mesh(projGeo, projMat);
      globeGroup.add(projMesh);

      projectileMeshes.push({
        mesh: projMesh,
        curve,
        progress: Math.random(),
        speed: 0.004 + Math.random() * 0.006
      });
    });

    // 7. Interactive Drag Orbit & Mouse Controls
    let isDragging = false;
    let prevMouseX = 0;
    let prevMouseY = 0;

    const onMouseDown = (e: MouseEvent) => {
      isDragging = true;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    };

    const onMouseMove = (e: MouseEvent) => {
      if (!isDragging) return;
      const deltaX = e.clientX - prevMouseX;
      const deltaY = e.clientY - prevMouseY;
      globeGroup.rotation.y += deltaX * 0.005;
      globeGroup.rotation.x += deltaY * 0.005;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    };

    const onMouseUp = () => {
      isDragging = false;
    };

    container.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);

    // Initial orientation: position North America / target facing camera
    globeGroup.rotation.y = -1.2;
    globeGroup.rotation.x = 0.3;

    // 8. Animation Loop
    let animId: number;
    let ringScale = 1;

    const animate = () => {
      // Auto-rotation if user is not actively dragging
      if (autoRotate && !isDragging) {
        globeGroup.rotation.y += 0.0018;
      }

      // Enclave ping pulse
      ringScale += 0.012;
      if (ringScale > 2.2) ringScale = 1;
      enclaveRing.scale.set(ringScale, ringScale, 1);
      (enclaveRing.material as THREE.MeshBasicMaterial).opacity = Math.max(0, 1 - (ringScale - 1) / 1.2);

      // Update ballistic projectile positions
      projectileMeshes.forEach(p => {
        p.progress += p.speed;
        if (p.progress > 1) {
          p.progress = 0;
        }
        const point = p.curve.getPoint(p.progress);
        p.mesh.position.copy(point);
      });

      renderer.render(scene, camera);
      animId = requestAnimationFrame(animate);
    };

    animate();

    const handleResize = () => {
      if (!container) return;
      const newW = container.clientWidth;
      const newH = container.clientHeight || 520;
      camera.aspect = newW / newH;
      camera.updateProjectionMatrix();
      renderer.setSize(newW, newH);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animId);
      container.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      window.removeEventListener('resize', handleResize);
      renderer.dispose();
    };
  }, [threatData, autoRotate]);

  return (
    <div className="space-y-4">
      {/* Top Banner Status Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl border border-indigo-500/20 bg-[#12111B]">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-rose-950/60 border border-rose-500/30 text-rose-400">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-white font-grotesk">
                Global Threat Intercept Globe (3D WebGL)
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-900/60 text-rose-300 border border-rose-500/30 font-bold">
                {threatData?.global_threat_index || 'DEFCON 2'}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Live orbital projection of adversary vectors inbound to Protected Enclave
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="text-right">
            <span className="text-slate-400 block text-[10px]">INGRESS INBOUND TELEMETRY</span>
            <span className="text-emerald-400 font-bold">
              {threatData?.inbound_rate_eps || 1420} EPS / Sec
            </span>
          </div>

          <button
            onClick={() => {
              sound.playTick();
              setAutoRotate(!autoRotate);
            }}
            className={`px-3 py-1.5 rounded-lg border text-xs font-sans transition-all flex items-center gap-1.5 ${
              autoRotate
                ? 'bg-indigo-600 text-white border-indigo-500 shadow-glow-indigo'
                : 'bg-[#181628] text-slate-400 border-white/10 hover:text-white'
            }`}
          >
            <Rotate3d className="w-3.5 h-3.5" />
            <span>{autoRotate ? 'Auto-Orbit: ON' : 'Auto-Orbit: OFF'}</span>
          </button>
        </div>
      </div>

      {/* Main 3D Globe + Inbound Vector List (2-Col Layout) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* 3D Canvas Container (8 cols) */}
        <div className="lg:col-span-8 relative bonanza-card rounded-2xl border border-indigo-500/20 bg-[#07060D] overflow-hidden min-h-[520px] flex items-center justify-center shadow-2xl">
          {/* Subtle Ambient Radial Glow */}
          <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_center,rgba(99,102,241,0.08)_0%,transparent_70%)]" />

          {/* Three.js Canvas Container */}
          <div ref={containerRef} className="w-full h-[520px] cursor-grab active:cursor-grabbing" />

          {/* Canvas Floating HUD Pill */}
          <div className="absolute top-4 left-4 bg-[#12111B]/80 backdrop-blur-md border border-white/10 px-3 py-1.5 rounded-xl text-[11px] font-mono text-slate-300 flex items-center gap-2 pointer-events-none">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></div>
            <span>TARGET: {threatData?.target_enclave.name || 'AWS us-west-1'}</span>
          </div>

          <div className="absolute bottom-4 left-4 right-4 flex items-center justify-between text-[11px] font-mono text-slate-400 pointer-events-none">
            <div className="flex items-center gap-3 bg-[#12111B]/80 backdrop-blur-md px-3 py-1.5 rounded-xl border border-white/5">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span> Critical ({threatData?.active_vectors.filter(v => v.severity === 'CRITICAL').length})
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-amber-500"></span> High / Med ({threatData?.active_vectors.filter(v => v.severity !== 'CRITICAL').length})
              </span>
              <span className="flex items-center gap-1 text-emerald-400">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span> Protected Enclave
              </span>
            </div>

            <span className="hidden sm:inline bg-[#12111B]/80 backdrop-blur-md px-3 py-1.5 rounded-xl border border-white/5">
              Drag to rotate • Inbound Ballistic Trajectories
            </span>
          </div>
        </div>

        {/* Inbound Attack Stream Feed (4 cols) */}
        <div className="lg:col-span-4 space-y-3">
          <div className="flex items-center justify-between border-b border-white/10 pb-2">
            <div className="flex items-center gap-2">
              <Flame className="w-4 h-4 text-rose-400" />
              <h4 className="text-sm font-bold text-white font-grotesk">
                Inbound Threat Vectors ({threatData?.active_vectors.length || 0})
              </h4>
            </div>
            <span className="text-[10px] font-mono text-slate-400">REAL-TIME</span>
          </div>

          <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-indigo-900">
            {threatData?.active_vectors.map(adv => {
              const isSelected = selectedVector?.id === adv.id;
              const isCritical = adv.severity === 'CRITICAL';

              return (
                <div
                  key={adv.id}
                  onClick={() => {
                    sound.playTick();
                    setSelectedVector(adv);
                  }}
                  className={`p-3 rounded-xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-[#181628] border-indigo-500 shadow-md shadow-indigo-500/10'
                      : 'bg-[#12111B] border-white/5 hover:border-indigo-500/30'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-white">
                          {adv.city}, {adv.country}
                        </span>
                        <span className="text-[10px] font-mono text-slate-400">
                          [{adv.country_code}]
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-rose-300 mt-0.5">
                        {adv.ip}
                      </div>
                    </div>
                    <span
                      className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${
                        isCritical
                          ? 'bg-rose-950 text-rose-300 border border-rose-500/40'
                          : 'bg-amber-950 text-amber-300 border border-amber-500/40'
                      }`}
                    >
                      {adv.severity}
                    </span>
                  </div>

                  <div className="mt-2 text-xs text-slate-300 font-sans line-clamp-1">
                    {adv.attack_type}
                  </div>

                  <div className="mt-2 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-400">
                    <span>MITRE: {adv.technique}</span>
                    <span className="text-indigo-400">{adv.bandwidth}</span>
                    <span className="text-rose-400 font-bold">RISK: {adv.risk_score}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
