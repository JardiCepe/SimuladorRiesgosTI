#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

rm -rf out dist
mkdir -p out/main out/test dist

echo "[1/4] Compilando código fuente (src)..."
javac -encoding UTF-8 -d out/main $(find src -name "*.java")

echo "[2/4] Compilando pruebas unitarias e integración (test)..."
javac -encoding UTF-8 -cp out/main -d out/test $(find test -name "*.java")

echo "[3/4] Ejecutando suite de pruebas..."
java -cp out/main:out/test com.auditoria.SimuladorTestRunner

echo "[4/4] Empaquetando SimuladorCiberseguridad.jar..."
jar cfm dist/SimuladorCiberseguridad.jar MANIFEST.MF -C out/main .

echo "Compilación y empaquetado exitosos: dist/SimuladorCiberseguridad.jar"
echo "Ejecutar con: java -jar dist/SimuladorCiberseguridad.jar"
