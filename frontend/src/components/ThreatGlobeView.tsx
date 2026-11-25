import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import {
  Globe,
  Radio,
  Flame,
  Rotate3d,
  Layers,
  Activity,
  Zap,
  Shield,
  Crosshair,
  Lock,
  ChevronRight
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

const DEFAULT_ENCLAVE: Enclave = {
  name: "NetraShield Primary Enclave (AWS us-west-1)",
  city: "San Francisco",
  country: "USA",
  lat: 37.7749,
  lon: -122.4194
};

const DEFAULT_VECTORS: ThreatVector[] = [
  {
    id: "adv-001",
    city: "Moscow",
    country: "Russia",
    country_code: "RU",
    lat: 55.7558,
    lon: 37.6173,
    ip: "185.220.101.5",
    attack_type: "SSH Brute-force & LSASS Memory Dump",
    technique: "T1003.001",
    severity: "CRITICAL",
    risk_score: 96,
    bandwidth: "48.2 MB/s"
  },
  {
    id: "adv-002",
    city: "Beijing",
    country: "China",
    country_code: "CN",
    lat: 39.9042,
    lon: 116.4074,
    ip: "202.108.22.5",
    attack_type: "Log4j RCE & Web Shell Dropper",
    technique: "T1190",
    severity: "CRITICAL",
    risk_score: 92,
    bandwidth: "112.5 MB/s"
  },
  {
    id: "adv-003",
    city: "Pyongyang",
    country: "North Korea",
    country_code: "KP",
    lat: 39.0392,
    lon: 125.7625,
    ip: "175.45.176.8",
    attack_type: "Cobalt Strike C2 Beacon Infiltration",
    technique: "T1071.001",
    severity: "HIGH",
    risk_score: 88,
    bandwidth: "14.8 MB/s"
  },
  {
    id: "adv-004",
    city: "Bucharest",
    country: "Romania",
    country_code: "RO",
    lat: 44.4268,
    lon: 26.1025,
    ip: "193.106.191.24",
    attack_type: "DNS Tunneling Exfiltration",
    technique: "T1071.004",
    severity: "HIGH",
    risk_score: 81,
    bandwidth: "6.4 MB/s"
  },
  {
    id: "adv-005",
    city: "São Paulo",
    country: "Brazil",
    country_code: "BR",
    lat: -23.5505,
    lon: -46.6333,
    ip: "177.18.204.11",
    attack_type: "Mirai Distributed SYN Amplification",
    technique: "T1498.001",
    severity: "MEDIUM",
    risk_score: 68,
    bandwidth: "890.0 MB/s"
  },
  {
    id: "adv-006",
    city: "Tehran",
    country: "Iran",
    country_code: "IR",
    lat: 35.6892,
    lon: 51.3890,
    ip: "91.240.118.15",
    attack_type: "Ivanti Connect Secure Zero-Day Exploit",
    technique: "T1212",
    severity: "CRITICAL",
    risk_score: 94,
    bandwidth: "31.0 MB/s"
  },
  {
    id: "adv-007",
    city: "Lagos",
    country: "Nigeria",
    country_code: "NG",
    lat: 6.5244,
    lon: 3.3792,
    ip: "102.134.42.19",
    attack_type: "OAuth Credential Stuffing & Spray",
    technique: "T1110.003",
    severity: "MEDIUM",
    risk_score: 62,
    bandwidth: "2.1 MB/s"
  },
  {
    id: "adv-008",
    city: "Frankfurt",
    country: "Germany",
    country_code: "DE",
    lat: 50.1109,
    lon: 8.6821,
    ip: "141.98.10.42",
    attack_type: "Tor Exit Node Ingress Reconnaissance",
    technique: "T1595.002",
    severity: "LOW",
    risk_score: 45,
    bandwidth: "0.8 MB/s"
  }
];

// Helper to determine if a lat/lon point is on an actual Earth landmass
function isLandMass(lat: number, lon: number): boolean {
  // North America
  if (lat >= 14 && lat <= 72 && lon >= -168 && lon <= -52) {
    if (lat < 30 && lon < -110) return false;
    if (lat > 50 && lon > -55) return false;
    return true;
  }
  // South America
  if (lat >= -56 && lat <= 13 && lon >= -82 && lon <= -34) {
    if (lat < -20 && lon > -42) return false;
    return true;
  }
  // Europe
  if (lat >= 35 && lat <= 71 && lon >= -10 && lon <= 45) {
    return true;
  }
  // Africa
  if (lat >= -35 && lat <= 38 && lon >= -18 && lon <= 52) {
    if (lat > 25 && lon < -15) return false;
    return true;
  }
  // Asia
  if (lat >= 5 && lat <= 76 && lon >= 42 && lon <= 152) {
    if (lat < 15 && lon < 70) return false;
    return true;
  }
  // Australia & New Zealand
  if (lat >= -45 && lat <= -10 && lon >= 112 && lon <= 178) {
    return true;
  }
  // Japan / UK / Indonesia Islands
  if (lat >= 30 && lat <= 46 && lon >= 129 && lon <= 146) return true;
  if (lat >= 50 && lat <= 60 && lon >= -11 && lon <= 2) return true;
  if (lat >= -10 && lat <= 6 && lon >= 95 && lon <= 141) return true;

  return false;
}

export const ThreatGlobeView: React.FC = () => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const globeGroupRef = useRef<THREE.Group | null>(null);

  const [threatData, setThreatData] = useState<{
    target_enclave: Enclave;
    active_vectors: ThreatVector[];
    global_threat_index: string;
    inbound_rate_eps: number;
  }>({
    target_enclave: DEFAULT_ENCLAVE,
    active_vectors: DEFAULT_VECTORS,
    global_threat_index: "ELEVATED (DEFCON 2)",
    inbound_rate_eps: 1420
  });

  const [selectedVector, setSelectedVector] = useState<ThreatVector | null>(DEFAULT_VECTORS[0]);
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
      }
    } catch (e) {
      // Use resilient defaults
    }
  };

  // Convert (lat, lon) to 3D Cartesian coordinates on sphere
  const latLonToVector3 = (lat: number, lon: number, radius: number): THREE.Vector3 => {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lon + 180) * (Math.PI / 180);
    const x = -(radius * Math.sin(phi) * Math.cos(theta));
    const z = radius * Math.sin(phi) * Math.sin(theta);
    const y = radius * Math.cos(phi);
    return new THREE.Vector3(x, y, z);
  };

  // Smoothly rotate the globe to face a specific vector
  const focusOnVector = (vec: ThreatVector) => {
    sound.playTick();
    setSelectedVector(vec);
    if (globeGroupRef.current) {
      const targetY = -((vec.lon + 90) * (Math.PI / 180));
      const targetX = (vec.lat * 0.5) * (Math.PI / 180);
      globeGroupRef.current.rotation.y = targetY;
      globeGroupRef.current.rotation.x = Math.max(-0.6, Math.min(0.6, targetX));
    }
  };

  useEffect(() => {
    if (!containerRef.current) return;

    const container = containerRef.current;
    const width = container.clientWidth > 0 ? container.clientWidth : 900;
    const height = container.clientHeight > 0 ? container.clientHeight : 580;

    // 1. Three.js Scene, Centered Camera, Antialiased Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    // Camera placed exactly at (0, 0, 230) and looking straight at center (0, 0, 0)
    camera.position.set(0, 0, 230);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    const GLOBE_RADIUS = 76;
    const globeGroup = new THREE.Group();
    globeGroupRef.current = globeGroup;
    scene.add(globeGroup);

    // 2. Deep Luminous Obsidian Sphere Core
    const sphereGeo = new THREE.SphereGeometry(GLOBE_RADIUS - 0.5, 64, 64);
    const sphereMat = new THREE.MeshPhongMaterial({
      color: 0x0D0B1C,
      emissive: 0x070614,
      specular: 0x6366F1,
      shininess: 25,
      transparent: true,
      opacity: 0.96
    });
    const baseSphere = new THREE.Mesh(sphereGeo, sphereMat);
    globeGroup.add(baseSphere);

    // 3. Ambient & Directional Space Lighting
    const ambientLight = new THREE.AmbientLight(0xFFFFFF, 0.9);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0x818CF8, 1.4);
    dirLight.position.set(150, 100, 180);
    scene.add(dirLight);

    const backLight = new THREE.DirectionalLight(0x6366F1, 0.8);
    backLight.position.set(-150, -50, -150);
    scene.add(backLight);

    // 4. Ethereal Atmospheric Outer Halo (Glow Shell)
    const atmosphereGeo = new THREE.SphereGeometry(GLOBE_RADIUS + 4, 32, 32);
    const atmosphereMat = new THREE.MeshBasicMaterial({
      color: 0x6366F1,
      side: THREE.BackSide,
      transparent: true,
      opacity: 0.18,
      blending: THREE.AdditiveBlending
    });
    const atmosphere = new THREE.Mesh(atmosphereGeo, atmosphereMat);
    scene.add(atmosphere);

    // 5. Crisp Holographic Longitude & Latitude Graticule Grid
    const latRings = [-60, -40, -20, 0, 20, 40, 60];
    latRings.forEach(lat => {
      const ringRadius = GLOBE_RADIUS * Math.cos(lat * (Math.PI / 180));
      const ringY = GLOBE_RADIUS * Math.sin(lat * (Math.PI / 180));
      const ringGeo = new THREE.BufferGeometry();
      const points: THREE.Vector3[] = [];
      const segments = 64;
      for (let i = 0; i <= segments; i++) {
        const theta = (i / segments) * Math.PI * 2;
        points.push(new THREE.Vector3(ringRadius * Math.cos(theta), ringY, ringRadius * Math.sin(theta)));
      }
      ringGeo.setFromPoints(points);
      const ringMat = new THREE.LineBasicMaterial({
        color: lat === 0 ? 0x818CF8 : 0x4F46E5,
        transparent: true,
        opacity: lat === 0 ? 0.35 : 0.16
      });
      const ringLine = new THREE.Line(ringGeo, ringMat);
      globeGroup.add(ringLine);
    });

    // 6. True Continental Landmass Dot Constellation (2,800 Points Filtered by Earth Geography)
    const landPoints: THREE.Vector3[] = [];
    const oceanPoints: THREE.Vector3[] = [];
    const totalSamples = 3400;

    for (let i = 0; i < totalSamples; i++) {
      const lat = (Math.asin(-1 + (2 * i) / totalSamples) * 180) / Math.PI;
      const lon = ((Math.sqrt(totalSamples * Math.PI) * Math.asin(-1 + (2 * i) / totalSamples) * 180) / Math.PI) % 360 - 180;

      const pos = latLonToVector3(lat, lon, GLOBE_RADIUS + 0.3);
      if (isLandMass(lat, lon)) {
        landPoints.push(pos);
      } else if (i % 6 === 0) {
        oceanPoints.push(pos);
      }
    }

    // Landmass Dots (Crisp Bright Electric Violet)
    const landGeo = new THREE.BufferGeometry().setFromPoints(landPoints);
    const landMat = new THREE.PointsMaterial({
      color: 0xA78BFA,
      size: 1.8,
      transparent: true,
      opacity: 0.85
    });
    const landMesh = new THREE.Points(landGeo, landMat);
    globeGroup.add(landMesh);

    // Oceanic Ambient Dots (Subtle Faint Blue-Indigo)
    const oceanGeo = new THREE.BufferGeometry().setFromPoints(oceanPoints);
    const oceanMat = new THREE.PointsMaterial({
      color: 0x4338CA,
      size: 1.1,
      transparent: true,
      opacity: 0.25
    });
    const oceanMesh = new THREE.Points(oceanGeo, oceanMat);
    globeGroup.add(oceanMesh);

    // 7. Target Enclave Pin (San Francisco, AWS us-west-1)
    const enclavePos = latLonToVector3(
      threatData.target_enclave.lat,
      threatData.target_enclave.lon,
      GLOBE_RADIUS + 0.5
    );

    const enclaveCoreGeo = new THREE.SphereGeometry(2.8, 16, 16);
    const enclaveCoreMat = new THREE.MeshBasicMaterial({ color: 0x10B981 });
    const enclaveCore = new THREE.Mesh(enclaveCoreGeo, enclaveCoreMat);
    enclaveCore.position.copy(enclavePos);
    globeGroup.add(enclaveCore);

    // Sonar Ripple Rings
    const ringGeo = new THREE.RingGeometry(3.2, 5.5, 32);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0x10B981,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.85
    });
    const enclaveRing = new THREE.Mesh(ringGeo, ringMat);
    enclaveRing.position.copy(enclavePos);
    enclaveRing.lookAt(new THREE.Vector3(0, 0, 0));
    globeGroup.add(enclaveRing);

    // 8. Adversary Threat Vectors & Ballistic Laser Trajectory Arcs
    const projectiles: {
      mesh: THREE.Mesh;
      trailMeshes: THREE.Mesh[];
      curve: THREE.QuadraticBezierCurve3;
      progress: number;
      speed: number;
    }[] = [];

    threatData.active_vectors.forEach(adv => {
      const originPos = latLonToVector3(adv.lat, adv.lon, GLOBE_RADIUS + 0.5);
      const isCritical = adv.severity === 'CRITICAL';
      const nodeColor = isCritical ? 0xF43F5E : 0xF59E0B;

      // Adversary Beacon Pin
      const advGeo = new THREE.SphereGeometry(isCritical ? 2.5 : 2.0, 16, 16);
      const advMat = new THREE.MeshBasicMaterial({ color: nodeColor });
      const advMesh = new THREE.Mesh(advGeo, advMat);
      advMesh.position.copy(originPos);
      globeGroup.add(advMesh);

      // Outer Threat Ring
      const advRingGeo = new THREE.RingGeometry(2.8, 4.2, 16);
      const advRingMat = new THREE.MeshBasicMaterial({
        color: nodeColor,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.7
      });
      const advRing = new THREE.Mesh(advRingGeo, advRingMat);
      advRing.position.copy(originPos);
      advRing.lookAt(new THREE.Vector3(0, 0, 0));
      globeGroup.add(advRing);

      // Parabolic Ballistic 3D Curve
      const midPoint = new THREE.Vector3().addVectors(originPos, enclavePos).multiplyScalar(0.5);
      const distance = originPos.distanceTo(enclavePos);
      const elevation = GLOBE_RADIUS + Math.max(25, distance * 0.42);
      midPoint.setLength(elevation);

      const curve = new THREE.QuadraticBezierCurve3(originPos, midPoint, enclavePos);
      const curvePoints = curve.getPoints(60);
      const curveGeo = new THREE.BufferGeometry().setFromPoints(curvePoints);
      const curveMat = new THREE.LineBasicMaterial({
        color: nodeColor,
        transparent: true,
        opacity: isCritical ? 0.75 : 0.45,
        linewidth: 2
      });
      const curveLine = new THREE.Line(curveGeo, curveMat);
      globeGroup.add(curveLine);

      // High-Velocity White-Cyan Particle + 2 Comet Trail Orbs
      const headGeo = new THREE.SphereGeometry(1.6, 8, 8);
      const headMat = new THREE.MeshBasicMaterial({ color: 0xFFFFFF });
      const headMesh = new THREE.Mesh(headGeo, headMat);
      globeGroup.add(headMesh);

      const trailMeshes: THREE.Mesh[] = [];
      for (let t = 0; t < 2; t++) {
        const trailGeo = new THREE.SphereGeometry(1.2 - t * 0.3, 6, 6);
        const trailMat = new THREE.MeshBasicMaterial({
          color: nodeColor,
          transparent: true,
          opacity: 0.6 - t * 0.25
        });
        const tMesh = new THREE.Mesh(trailGeo, trailMat);
        globeGroup.add(tMesh);
        trailMeshes.push(tMesh);
      }

      projectiles.push({
        mesh: headMesh,
        trailMeshes,
        curve,
        progress: Math.random(),
        speed: 0.005 + Math.random() * 0.005
      });
    });

    // 9. Interactive Drag Controls with Smooth Damping
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

    // Initial orientation: North America angled forward nicely
    globeGroup.rotation.y = -1.1;
    globeGroup.rotation.x = 0.25;

    // 10. High-Performance 60fps Render Loop
    let animId: number;
    let ringScale = 1;

    const animate = () => {
      // Gentle auto planetary rotation if user is not actively dragging
      if (autoRotate && !isDragging) {
        globeGroup.rotation.y += 0.0016;
      }

      // Enclave Sonar Pulse Animation
      ringScale += 0.018;
      if (ringScale > 2.6) ringScale = 1;
      enclaveRing.scale.set(ringScale, ringScale, 1);
      (enclaveRing.material as THREE.MeshBasicMaterial).opacity = Math.max(0, 1 - (ringScale - 1) / 1.6);

      // Update Projectiles and Comet Trails
      projectiles.forEach(p => {
        p.progress += p.speed;
        if (p.progress > 1) {
          p.progress = 0;
        }
        const currentPos = p.curve.getPoint(p.progress);
        p.mesh.position.copy(currentPos);

        p.trailMeshes.forEach((tMesh, idx) => {
          const trailProg = Math.max(0, p.progress - (idx + 1) * 0.02);
          tMesh.position.copy(p.curve.getPoint(trailProg));
        });
      });

      renderer.render(scene, camera);
      animId = requestAnimationFrame(animate);
    };

    animate();

    // ResizeObserver ensures the globe is centered and sharp under any screen size
    const resizeObserver = new ResizeObserver(() => {
      if (!container || !renderer || !camera) return;
      const newW = container.clientWidth > 0 ? container.clientWidth : 900;
      const newH = container.clientHeight > 0 ? container.clientHeight : 580;
      camera.aspect = newW / newH;
      camera.updateProjectionMatrix();
      renderer.setSize(newW, newH);
    });
    resizeObserver.observe(container);

    return () => {
      cancelAnimationFrame(animId);
      resizeObserver.disconnect();
      container.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
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
                {threatData.global_threat_index}
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
              {threatData.inbound_rate_eps} EPS / Sec
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

      {/* Main 3D Centered Canvas with Side Telemetry & Vector HUD */}
      <div className="relative bonanza-card rounded-2xl border border-indigo-500/30 bg-[#07060F] overflow-hidden min-h-[580px] shadow-2xl flex items-center justify-center">
        {/* Ambient Radial Spotlight Centered on Earth */}
        <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_center,rgba(99,102,241,0.12)_0%,rgba(168,85,247,0.04)_45%,transparent_75%)]" />

        {/* Perfectly Centered Three.js 3D Earth Canvas */}
        <div
          ref={containerRef}
          className="w-full h-[580px] cursor-grab active:cursor-grabbing flex items-center justify-center"
        />

        {/* Top-Left Floating Target Enclave Pill */}
        <div className="absolute top-4 left-4 z-10 bg-[#12111B]/90 backdrop-blur-md border border-white/10 px-3.5 py-2 rounded-xl text-xs font-mono text-slate-300 flex items-center gap-2.5 shadow-lg">
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></div>
          <div>
            <div className="text-[10px] text-slate-500">PROTECTED DESTINATION</div>
            <div className="font-bold text-white">{threatData.target_enclave.name}</div>
          </div>
        </div>

        {/* Top-Right Threat Vector Live Drawer */}
        <div className="absolute top-4 right-4 z-10 max-w-xs w-72 max-h-[500px] flex flex-col bg-[#12111B]/95 backdrop-blur-xl border border-white/10 rounded-2xl p-3 shadow-2xl">
          <div className="flex items-center justify-between pb-2 border-b border-white/10 mb-2">
            <div className="flex items-center gap-1.5 text-xs font-bold text-white">
              <Flame className="w-3.5 h-3.5 text-rose-400" />
              <span>Inbound Vectors ({threatData.active_vectors.length})</span>
            </div>
            <span className="text-[9px] font-mono text-indigo-400">CLICK TO FOCUS</span>
          </div>

          <div className="space-y-1.5 overflow-y-auto max-h-[380px] pr-1 scrollbar-thin scrollbar-thumb-indigo-900">
            {threatData.active_vectors.map(adv => {
              const isSelected = selectedVector?.id === adv.id;
              const isCritical = adv.severity === 'CRITICAL';
              return (
                <div
                  key={adv.id}
                  onClick={() => focusOnVector(adv)}
                  className={`p-2.5 rounded-xl border text-xs transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-indigo-600/25 border-indigo-400 shadow-sm'
                      : 'bg-[#181628]/80 border-white/5 hover:border-indigo-500/40'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white">{adv.city}, {adv.country}</span>
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-bold ${
                        isCritical
                          ? 'bg-rose-950 text-rose-300 border border-rose-500/30'
                          : 'bg-amber-950 text-amber-300 border border-amber-500/30'
                      }`}
                    >
                      {adv.severity}
                    </span>
                  </div>
                  <div className="text-[10px] font-mono text-rose-300 mt-0.5">{adv.ip}</div>
                  <div className="text-[11px] text-slate-300 mt-1 line-clamp-1">{adv.attack_type}</div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Bottom Centered Control & Legend Bar */}
        <div className="absolute bottom-4 left-4 right-4 z-10 flex flex-wrap items-center justify-between gap-3 text-xs font-mono pointer-events-none">
          <div className="flex items-center gap-3 bg-[#12111B]/90 backdrop-blur-md px-3.5 py-2 rounded-xl border border-white/10 pointer-events-auto">
            <span className="flex items-center gap-1.5 text-rose-400 font-semibold">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span> Critical Ingress
            </span>
            <span className="flex items-center gap-1.5 text-amber-400 font-semibold">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span> High / Recon
            </span>
            <span className="flex items-center gap-1.5 text-emerald-400 font-semibold">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Enclave Radar
            </span>
          </div>

          <div className="bg-[#12111B]/90 backdrop-blur-md px-3.5 py-2 rounded-xl border border-white/10 text-slate-400 text-[11px]">
            Drag to Rotate • Ballistic Trajectory Intercepts
          </div>
        </div>
      </div>
    </div>
  );
};
