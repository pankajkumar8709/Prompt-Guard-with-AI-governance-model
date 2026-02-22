import { useRef } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { Sphere } from '@react-three/drei'
import * as THREE from 'three'

function ThreatGlobe() {
  const globeRef = useRef<THREE.Mesh>(null)
  const arcsRef = useRef<THREE.Group>(null)

  useFrame((state) => {
    if (globeRef.current) {
      globeRef.current.rotation.y += 0.001
    }
    if (arcsRef.current) {
      arcsRef.current.rotation.y += 0.001
    }
  })

  // Threat nodes (random positions on sphere)
  const nodes = [
    { lat: 40.7128, lon: -74.0060 }, // New York
    { lat: 51.5074, lon: -0.1278 },  // London
    { lat: 35.6762, lon: 139.6503 }, // Tokyo
    { lat: -33.8688, lon: 151.2093 }, // Sydney
    { lat: 1.3521, lon: 103.8198 },  // Singapore
  ]

  const latLonToVector3 = (lat: number, lon: number, radius: number) => {
    const phi = (90 - lat) * (Math.PI / 180)
    const theta = (lon + 180) * (Math.PI / 180)
    return new THREE.Vector3(
      -radius * Math.sin(phi) * Math.cos(theta),
      radius * Math.cos(phi),
      radius * Math.sin(phi) * Math.sin(theta)
    )
  }

  return (
    <group>
      {/* Wireframe Globe */}
      <Sphere ref={globeRef} args={[2, 32, 32]}>
        <meshBasicMaterial
          color="#00E5FF"
          wireframe
          transparent
          opacity={0.15}
        />
      </Sphere>

      {/* Threat Nodes */}
      <group ref={arcsRef}>
        {nodes.map((node, i) => {
          const pos = latLonToVector3(node.lat, node.lon, 2)
          return (
            <mesh key={i} position={pos}>
              <sphereGeometry args={[0.03, 8, 8]} />
              <meshBasicMaterial color="#FF4560" />
              <pointLight color="#FF4560" intensity={2} distance={0.5} />
            </mesh>
          )
        })}

        {/* Attack Arcs */}
        {nodes.slice(0, -1).map((node, i) => {
          const start = latLonToVector3(node.lat, node.lon, 2)
          const end = latLonToVector3(nodes[i + 1].lat, nodes[i + 1].lon, 2)
          const mid = new THREE.Vector3()
            .addVectors(start, end)
            .multiplyScalar(0.5)
            .normalize()
            .multiplyScalar(2.5)

          const curve = new THREE.QuadraticBezierCurve3(start, mid, end)
          const points = curve.getPoints(50)
          const geometry = new THREE.BufferGeometry().setFromPoints(points)

          return (
            <line key={i} geometry={geometry}>
              <lineBasicMaterial
                color={i % 2 === 0 ? '#FF4560' : '#FFB800'}
                transparent
                opacity={0.6}
                linewidth={2}
              />
            </line>
          )
        })}
      </group>
    </group>
  )
}

export function Globe3D() {
  return (
    <div className="absolute inset-0 flex items-center justify-center">
      <Canvas camera={{ position: [0, 0, 5], fov: 50 }}>
        <ambientLight intensity={0.5} />
        <ThreatGlobe />
      </Canvas>
      <div className="vignette" />
    </div>
  )
}
