package com.auditoria.negocio;

import com.auditoria.modelo.ActivoRed;
import com.auditoria.modelo.EnlaceRed;
import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class SimuladorPropagacion {

    public static class NodoComprometido {
        private final ActivoRed activo;
        private final int salto;
        private final String origenId;
        private final String idEnlace;
        private final double probSalto;
        private final double probAcumulada;

        public NodoComprometido(ActivoRed activo, int salto, String origenId,
                                String idEnlace, double probSalto, double probAcumulada) {
            this.activo = activo;
            this.salto = salto;
            this.origenId = origenId;
            this.idEnlace = idEnlace;
            this.probSalto = probSalto;
            this.probAcumulada = probAcumulada;
        }

        public ActivoRed getActivo() {
            return activo;
        }

        public int getSalto() {
            return salto;
        }

        public String getOrigenId() {
            return origenId;
        }

        public String getIdEnlace() {
            return idEnlace;
        }

        public double getProbSalto() {
            return probSalto;
        }

        public double getProbAcumulada() {
            return probAcumulada;
        }
    }

    public static class ResultadoSimulacion {
        private final ActivoRed pacienteCero;
        private final String vectorCompromiso;
        private final List<NodoComprometido> nodosComprometidos;
        private final double porcentajeRedAfectada;
        private final double indiceImpactoSistemico;

        public ResultadoSimulacion(ActivoRed pacienteCero, String vectorCompromiso,
                                   List<NodoComprometido> nodosComprometidos,
                                   double porcentajeRedAfectada, double indiceImpactoSistemico) {
            this.pacienteCero = pacienteCero;
            this.vectorCompromiso = vectorCompromiso;
            this.nodosComprometidos = new ArrayList<>(nodosComprometidos);
            this.porcentajeRedAfectada = porcentajeRedAfectada;
            this.indiceImpactoSistemico = indiceImpactoSistemico;
        }

        public ActivoRed getPacienteCero() {
            return pacienteCero;
        }

        public String getVectorCompromiso() {
            return vectorCompromiso;
        }

        public List<NodoComprometido> getNodosComprometidos() {
            return new ArrayList<>(nodosComprometidos);
        }

        public double getPorcentajeRedAfectada() {
            return porcentajeRedAfectada;
        }

        public double getIndiceImpactoSistemico() {
            return indiceImpactoSistemico;
        }
    }

    private final Map<String, EnlaceRed> enlaces;
    private ResultadoSimulacion ultimaSimulacion;

    public SimuladorPropagacion() {
        this.enlaces = new LinkedHashMap<>();
    }

    public void registrarEnlace(EnlaceRed enlace) throws AuditoriaException {
        if (enlace == null) {
            throw new AuditoriaException("El enlace de red no puede ser nulo.");
        }
        String id = enlace.getIdEnlace();
        if (enlaces.containsKey(id)) {
            throw new AuditoriaException("Ya existe un enlace con el ID: " + id);
        }
        for (EnlaceRed existente : enlaces.values()) {
            boolean mismoOrigen = existente.getOrigen().getIdActivo()
                    .equals(enlace.getOrigen().getIdActivo());
            boolean mismoDestino = existente.getDestino().getIdActivo()
                    .equals(enlace.getDestino().getIdActivo());
            boolean mismoMedio = existente.getTipoMedio().equalsIgnoreCase(enlace.getTipoMedio());
            if (mismoOrigen && mismoDestino && mismoMedio) {
                throw new AuditoriaException(
                        "Ya existe un enlace " + enlace.getTipoMedio() + " de "
                                + enlace.getOrigen().getIdActivo() + " hacia "
                                + enlace.getDestino().getIdActivo() + ".");
            }
        }
        enlaces.put(id, enlace);
    }

    public EnlaceRed buscarEnlacePorId(String idEnlace) throws AuditoriaException {
        String idNorm = ValidadorDatos.validarTextoNoVacio(idEnlace, "ID de Enlace").toUpperCase();
        EnlaceRed enlace = enlaces.get(idNorm);
        if (enlace == null) {
            throw new AuditoriaException("No se encontró el enlace con ID: " + idNorm);
        }
        return enlace;
    }

    public List<EnlaceRed> listarEnlaces() {
        return new ArrayList<>(enlaces.values());
    }

    public void actualizarEnlace(String idEnlace, String nuevoMedio, boolean activo)
            throws AuditoriaException {
        EnlaceRed enlace = buscarEnlacePorId(idEnlace);
        enlace.setTipoMedio(nuevoMedio);
        enlace.setActivo(activo);
    }

    public EnlaceRed eliminarEnlace(String idEnlace) throws AuditoriaException {
        EnlaceRed enlace = buscarEnlacePorId(idEnlace);
        enlaces.remove(enlace.getIdEnlace());
        return enlace;
    }

    public void eliminarEnlacesDeActivo(String idActivo) {
        if (idActivo == null) {
            return;
        }
        String idNorm = idActivo.trim().toUpperCase();
        Iterator<EnlaceRed> it = enlaces.values().iterator();
        while (it.hasNext()) {
            EnlaceRed e = it.next();
            if (e.getOrigen().getIdActivo().equals(idNorm)
                    || e.getDestino().getIdActivo().equals(idNorm)) {
                it.remove();
            }
        }
    }

    public void reiniciarSimulacion() {
        this.ultimaSimulacion = null;
    }

    // Construye la matriz de adyacencia N x N con la probabilidad de salto entre activos
    public double[][] construirMatrizAdyacencia(List<ActivoRed> activos) {
        int n = activos.size();
        double[][] matriz = new double[n][n];
        Map<String, Integer> indices = new HashMap<>();
        for (int i = 0; i < n; i++) {
            indices.put(activos.get(i).getIdActivo(), i);
        }
        for (EnlaceRed enlace : enlaces.values()) {
            if (!enlace.estaActivo()) {
                continue;
            }
            Integer i = indices.get(enlace.getOrigen().getIdActivo());
            Integer j = indices.get(enlace.getDestino().getIdActivo());
            if (i != null && j != null) {
                double prob = enlace.calcularProbSalto();
                if (prob > matriz[i][j]) {
                    matriz[i][j] = prob;
                }
            }
        }
        return matriz;
    }

    // Simulación recursiva de propagación desde el Paciente Cero
    public ResultadoSimulacion simularPropagacion(ActivoRed pacienteCero,
                                                    String vectorCompromiso,
                                                    List<ActivoRed> todosLosActivos)
            throws AuditoriaException {
        if (pacienteCero == null) {
            throw new AuditoriaException("Debe seleccionar un activo 'Paciente Cero' válido.");
        }
        String vectorLimpio = ValidadorDatos.validarTextoNoVacio(vectorCompromiso, "Vector de compromiso");
        double factorVector = calcularFactorVector(vectorLimpio);

        // Construir lista de adyacencia solo con enlaces activos
        Map<String, List<EnlaceRed>> adyacencia = new HashMap<>();
        for (EnlaceRed enlace : enlaces.values()) {
            if (enlace.estaActivo()) {
                String idOrig = enlace.getOrigen().getIdActivo();
                if (!adyacencia.containsKey(idOrig)) {
                    adyacencia.put(idOrig, new ArrayList<>());
                }
                adyacencia.get(idOrig).add(enlace);
            }
        }

        Map<String, NodoComprometido> comprometidos = new LinkedHashMap<>();
        comprometidos.put(
                pacienteCero.getIdActivo(),
                new NodoComprometido(pacienteCero, 0, "ORIGEN", "-", 1.0, 1.0));

        propagarRecursivo(pacienteCero, 0, 1.0, factorVector, adyacencia, comprometidos);

        // Ordenar resultados por número de salto ascendente
        List<NodoComprometido> ordenados = new ArrayList<>(comprometidos.values());
        for (int i = 0; i < ordenados.size() - 1; i++) {
            for (int j = 0; j < ordenados.size() - 1 - i; j++) {
                if (ordenados.get(j).getSalto() > ordenados.get(j + 1).getSalto()) {
                    NodoComprometido temp = ordenados.get(j);
                    ordenados.set(j, ordenados.get(j + 1));
                    ordenados.set(j + 1, temp);
                }
            }
        }

        int totalRed = todosLosActivos != null && !todosLosActivos.isEmpty()
                ? todosLosActivos.size()
                : ordenados.size();
        double porcentaje = Math.round(((ordenados.size() * 100.0) / totalRed) * 100.0) / 100.0;

        double impactoSistemico = 0.0;
        for (NodoComprometido nodo : ordenados) {
            ActivoRed a = nodo.getActivo();
            double severidadBase = Math.max(1.0, a.getPuntajeCVSS());
            impactoSistemico += severidadBase * a.calcularFactorCriticidad() * nodo.getProbAcumulada();
        }
        impactoSistemico = Math.round(impactoSistemico * 100.0) / 100.0;

        this.ultimaSimulacion = new ResultadoSimulacion(
                pacienteCero, vectorLimpio, ordenados, porcentaje, impactoSistemico);
        return this.ultimaSimulacion;
    }

    private void propagarRecursivo(ActivoRed actual, int saltoActual, double probActual,
                                   double factorVector, Map<String, List<EnlaceRed>> adyacencia,
                                   Map<String, NodoComprometido> comprometidos) {
        List<EnlaceRed> salientes = adyacencia.get(actual.getIdActivo());
        if (salientes == null) {
            return;
        }
        for (EnlaceRed enlace : salientes) {
            ActivoRed vecino = enlace.getDestino();
            double probSalto = Math.min(0.99, enlace.calcularProbSalto() * factorVector);
            double nuevaProbAcumulada = Math.round((probActual * probSalto) * 1000.0) / 1000.0;

            boolean vecinoVulnerable = vecino.getPuntajeCVSS() >= 3.5
                    || "Crítica".equals(vecino.getNivelExposicion())
                    || probSalto >= 0.65;

            if (!vecinoVulnerable || nuevaProbAcumulada < 0.15) {
                continue;
            }

            NodoComprometido previo = comprometidos.get(vecino.getIdActivo());
            if (previo == null || nuevaProbAcumulada > previo.getProbAcumulada() + 0.001) {
                comprometidos.put(
                        vecino.getIdActivo(),
                        new NodoComprometido(
                                vecino,
                                saltoActual + 1,
                                actual.getIdActivo(),
                                enlace.getIdEnlace(),
                                Math.round(probSalto * 100.0) / 100.0,
                                nuevaProbAcumulada));
                propagarRecursivo(vecino, saltoActual + 1, nuevaProbAcumulada,
                        factorVector, adyacencia, comprometidos);
            }
        }
    }

    private double calcularFactorVector(String vector) {
        String lower = vector.toLowerCase();
        if (lower.contains("ransomware") || lower.contains("gusano") || lower.contains("worm")) {
            return 1.15;
        }
        if (lower.contains("remoto")) {
            return 1.05;
        }
        return 0.95;
    }

    public ResultadoSimulacion getUltimaSimulacion() {
        return ultimaSimulacion;
    }
}
