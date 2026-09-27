import { useEffect, useRef, useState } from "react";
import * as THREE from "three";

interface ThreeManifoldProps {
  className?: string;
  themeStrategy?: "glass" | "minimalism" | "neomorphism";
}

export function ThreeManifold({ className = "", themeStrategy = "glass" }: ThreeManifoldProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [isWebGLAvailable, setIsWebGLAvailable] = useState(true);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // Check WebGL availability
    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) {
        setIsWebGLAvailable(false);
        return;
      }
    } catch {
      setIsWebGLAvailable(false);
      return;
    }

    // â”€â”€ Three.js Scene Setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const rect = container.getBoundingClientRect();
    const width = Math.floor(rect.width) || 300;
    const height = Math.floor(rect.height) || 300;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 18;

    const renderer = new THREE.WebGLRenderer({
      alpha: true,
      antialias: true,
      powerPreference: "high-performance",
    });
    renderer.setSize(width, height, false);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.domElement.style.width = "100%";
    renderer.domElement.style.height = "100%";
    renderer.domElement.style.maxWidth = "100%";
    renderer.domElement.style.display = "block";
    container.appendChild(renderer.domElement);

    // â”€â”€ Color Theme Mappings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Colors matching Flow दृष्टि tokens: signal-teal, watch-amber, void-800
    const tealColor = new THREE.Color(0x2dd4bf); // Signal Teal
    const amberColor = new THREE.Color(0xfbbf24); // Watch Amber
    const crimsonColor = new THREE.Color(0xf43f5e); // Critical Crimson

    // â”€â”€ Group 1: 54-D State-Space Geodesic Manifold â”€â”€â”€â”€â”€â”€â”€
    const manifoldGroup = new THREE.Group();
    scene.add(manifoldGroup);

    // Outer Geodesic Sphere
    const geoRadius = 5.2;
    const icosahedronGeo = new THREE.IcosahedronGeometry(geoRadius, 2);
    const wireframeMat = new THREE.MeshBasicMaterial({
      color: themeStrategy === "minimalism" ? 0x94a3b8 : tealColor,
      wireframe: true,
      transparent: true,
      opacity: themeStrategy === "glass" ? 0.35 : themeStrategy === "minimalism" ? 0.2 : 0.45,
    });
    const icosahedronMesh = new THREE.Mesh(icosahedronGeo, wireframeMat);
    manifoldGroup.add(icosahedronMesh);

    // Node Vertices (Points on the manifold vertices)
    const pointsGeo = new THREE.BufferGeometry();
    const posAttribute = icosahedronGeo.getAttribute("position");
    pointsGeo.setAttribute("position", posAttribute);
    const pointsMat = new THREE.PointsMaterial({
      color: tealColor,
      size: 0.18,
      transparent: true,
      opacity: 0.9,
    });
    const pointsMesh = new THREE.Points(pointsGeo, pointsMat);
    manifoldGroup.add(pointsMesh);

    // Inner Core Sphere (Latent Representation)
    const coreGeo = new THREE.SphereGeometry(2.4, 24, 24);
    const coreMat = new THREE.MeshStandardMaterial({
      color: 0x0f172a,
      roughness: 0.4,
      metalness: 0.8,
      emissive: themeStrategy === "minimalism" ? 0x0284c7 : 0x0d9488,
      emissiveIntensity: 0.3,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    manifoldGroup.add(coreMesh);

    // â”€â”€ Group 2: Dual Orbital Trajectory Rings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Ring 1: SparseRSSM Temporal State-Space Ring
    const ring1Geo = new THREE.TorusGeometry(6.6, 0.04, 16, 100);
    const ring1Mat = new THREE.MeshBasicMaterial({
      color: tealColor,
      transparent: true,
      opacity: 0.7,
    });
    const ring1Mesh = new THREE.Mesh(ring1Geo, ring1Mat);
    ring1Mesh.rotation.x = Math.PI / 3;
    ring1Mesh.rotation.y = Math.PI / 6;
    scene.add(ring1Mesh);

    // Ring 2: TFCNet Spectral Attention Ring
    const ring2Geo = new THREE.TorusGeometry(7.2, 0.04, 16, 100);
    const ring2Mat = new THREE.MeshBasicMaterial({
      color: amberColor,
      transparent: true,
      opacity: 0.55,
    });
    const ring2Mesh = new THREE.Mesh(ring2Geo, ring2Mat);
    ring2Mesh.rotation.x = -Math.PI / 4;
    ring2Mesh.rotation.y = Math.PI / 4;
    scene.add(ring2Mesh);

    // â”€â”€ Group 3: Particle Telemetry Cloud â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const particleCount = 280;
    const particleGeo = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount; i++) {
      const radius = 5.5 + Math.random() * 4.5;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);

      positions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
      positions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
      positions[i * 3 + 2] = radius * Math.cos(phi);

      const isAmber = Math.random() > 0.75;
      const c = isAmber ? amberColor : tealColor;
      colors[i * 3] = c.r;
      colors[i * 3 + 1] = c.g;
      colors[i * 3 + 2] = c.b;
    }

    particleGeo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    particleGeo.setAttribute("color", new THREE.BufferAttribute(colors, 3));

    const particleMat = new THREE.PointsMaterial({
      size: 0.12,
      vertexColors: true,
      transparent: true,
      opacity: 0.85,
    });
    const particleCloud = new THREE.Points(particleGeo, particleMat);
    scene.add(particleCloud);

    // â”€â”€ Lighting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.8);
    scene.add(ambientLight);

    const tealPointLight = new THREE.PointLight(0x2dd4bf, 2.5, 50);
    tealPointLight.position.set(10, 10, 10);
    scene.add(tealPointLight);

    const crimsonPointLight = new THREE.PointLight(0xf43f5e, 1.8, 40);
    crimsonPointLight.position.set(-10, -10, -10);
    scene.add(crimsonPointLight);

    // â”€â”€ Interactive Mouse Parallax â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let mouseX = 0;
    let mouseY = 0;
    let targetX = 0;
    let targetY = 0;

    const onPointerMove = (event: PointerEvent) => {
      const rect = container.getBoundingClientRect();
      const x = event.clientX - rect.left - rect.width / 2;
      const y = event.clientY - rect.top - rect.height / 2;
      targetX = (x / rect.width) * 1.5;
      targetY = -(y / rect.height) * 1.5;
    };

    window.addEventListener("pointermove", onPointerMove);

    // â”€â”€ Responsive Resize Observer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const resizeObserver = new ResizeObserver((entries) => {
      if (!container) return;
      for (const entry of entries) {
        const newWidth = Math.floor(entry.contentRect.width);
        const newHeight = Math.floor(entry.contentRect.height);
        if (newWidth > 0 && newHeight > 0) {
          camera.aspect = newWidth / newHeight;
          camera.updateProjectionMatrix();
          renderer.setSize(newWidth, newHeight, false);
        }
      }
    });
    resizeObserver.observe(container);

    // â”€â”€ Animation Loop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let animationFrameId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      const delta = clock.getDelta();
      const time = clock.getElapsedTime();

      // Smooth mouse lerp
      mouseX += (targetX - mouseX) * 0.05;
      mouseY += (targetY - mouseY) * 0.05;

      // Rotate manifold
      manifoldGroup.rotation.y += 0.25 * delta;
      manifoldGroup.rotation.x = mouseY * 0.4;
      manifoldGroup.rotation.y += mouseX * 0.02;

      // Pulse core
      const pulse = 1 + Math.sin(time * 2) * 0.04;
      coreMesh.scale.set(pulse, pulse, pulse);

      // Rotate orbital rings
      ring1Mesh.rotation.z += 0.35 * delta;
      ring2Mesh.rotation.z -= 0.45 * delta;

      // Rotate particle cloud
      particleCloud.rotation.y -= 0.08 * delta;
      particleCloud.rotation.x += 0.04 * delta;

      renderer.render(scene, camera);
      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    // â”€â”€ Cleanup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("pointermove", onPointerMove);
      resizeObserver.disconnect();

      // Dispose geometries & materials
      icosahedronGeo.dispose();
      wireframeMat.dispose();
      pointsGeo.dispose();
      pointsMat.dispose();
      coreGeo.dispose();
      coreMat.dispose();
      ring1Geo.dispose();
      ring1Mat.dispose();
      ring2Geo.dispose();
      ring2Mat.dispose();
      particleGeo.dispose();
      particleMat.dispose();
      renderer.dispose();

      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [themeStrategy]);

  if (!isWebGLAvailable) {
    return (
      <div className={`flex items-center justify-center rounded-2xl border border-teal/20 bg-void-800/40 p-8 text-center ${className}`}>
        <div>
          <div className="mx-auto size-16 rounded-full border-2 border-dashed border-teal/40 p-3 text-teal animate-spin" />
          <p className="mt-4 font-mono text-sm text-paper">54-Dimensional Neural Manifold</p>
          <p className="mt-1 text-xs text-fog">SparseRSSM + TFCNet Latent State Space</p>
        </div>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={`relative h-full w-full max-w-full cursor-grab active:cursor-grabbing overflow-hidden ${className}`}
      title="Interactive 3D Neural Manifold — Drag or move mouse to rotate 54-D state space"
    />
  );
}
