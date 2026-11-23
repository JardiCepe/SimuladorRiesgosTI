package com.auditoria.negocio;

import com.auditoria.modelo.AccionMitigacion;
import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class OptimizadorMitigacion {

    public static class PlanMitigacion {
        private final List<AccionMitigacion> accionesSeleccionadas;
        private final double presupuestoMaximo;
        private final double costoTotal;
        private final double horasTotales;
        private final double reduccionRiesgoTotal;
        private final double reduccionPonderada;

        public PlanMitigacion(List<AccionMitigacion> accionesSeleccionadas,
                              double presupuestoMaximo, double costoTotal,
                              double horasTotales, double reduccionRiesgoTotal,
                              double reduccionPonderada) {
            this.accionesSeleccionadas = new ArrayList<>(accionesSeleccionadas);
            this.presupuestoMaximo = presupuestoMaximo;
            this.costoTotal = costoTotal;
            this.horasTotales = horasTotales;
            this.reduccionRiesgoTotal = reduccionRiesgoTotal;
            this.reduccionPonderada = reduccionPonderada;
        }

        public List<AccionMitigacion> getAccionesSeleccionadas() {
            return new ArrayList<>(accionesSeleccionadas);
        }

        public double getPresupuestoMaximo() {
            return presupuestoMaximo;
        }

        public double getCostoTotal() {
            return costoTotal;
        }

        public double getPresupuestoRestante() {
            return Math.round((presupuestoMaximo - costoTotal) * 100.0) / 100.0;
        }

        public double getHorasTotales() {
            return horasTotales;
        }

        public double getReduccionRiesgoTotal() {
            return reduccionRiesgoTotal;
        }

        public double getReduccionPonderada() {
            return reduccionPonderada;
        }
    }

    private final Map<String, AccionMitigacion> acciones;

    public OptimizadorMitigacion() {
        this.acciones = new LinkedHashMap<>();
    }

    public void registrarAccion(AccionMitigacion accion) throws AuditoriaException {
        if (accion == null) {
            throw new AuditoriaException("La acción de mitigación no puede ser nula.");
        }
        String id = accion.getIdAccion();
        if (acciones.containsKey(id)) {
            throw new AuditoriaException("Ya existe una acción registrada con el ID: " + id);
        }
        acciones.put(id, accion);
    }

    public AccionMitigacion buscarAccionPorId(String idAccion) throws AuditoriaException {
        String idNorm = ValidadorDatos.validarTextoNoVacio(idAccion, "ID de Acción").toUpperCase();
        AccionMitigacion accion = acciones.get(idNorm);
        if (accion == null) {
            throw new AuditoriaException("No se encontró ninguna acción de mitigación con ID: " + idNorm);
        }
        return accion;
    }

    public List<AccionMitigacion> listarAcciones() {
        return new ArrayList<>(acciones.values());
    }

    public List<AccionMitigacion> listarAccionesPendientes() {
        List<AccionMitigacion> pendientes = new ArrayList<>();
        for (AccionMitigacion a : acciones.values()) {
            if (!a.isAplicada()) {
                pendientes.add(a);
            }
        }
        return pendientes;
    }

    public void actualizarAccion(String idAccion, String nuevoTipo, double nuevoCosto,
                                 double nuevasHoras, double nuevaReduccion) throws AuditoriaException {
        AccionMitigacion a = buscarAccionPorId(idAccion);
        a.setTipoAccion(nuevoTipo);
        a.setCostoEstimado(nuevoCosto);
        a.setHorasHombre(nuevasHoras);
        a.setReduccionRiesgo(nuevaReduccion);
    }

    public AccionMitigacion eliminarAccion(String idAccion) throws AuditoriaException {
        AccionMitigacion a = buscarAccionPorId(idAccion);
        acciones.remove(a.getIdAccion());
        return a;
    }

    public void eliminarAccionesDeActivo(String idActivo) {
        if (idActivo == null) {
            return;
        }
        String idNorm = idActivo.trim().toUpperCase();
        Iterator<AccionMitigacion> it = acciones.values().iterator();
        while (it.hasNext()) {
            if (it.next().getActivo().getIdActivo().equals(idNorm)) {
                it.remove();
            }
        }
    }

    // Algoritmo de la Mochila 0/1 con Programación Dinámica clásica
    public PlanMitigacion optimizarPlanMitigacion(
            double presupuestoMaximo,
            SimuladorPropagacion.ResultadoSimulacion simulacion) throws AuditoriaException {
        ValidadorDatos.validarPositivo(presupuestoMaximo, "Presupuesto disponible");

        // Guardar probabilidad de compromiso del Módulo 3 por activo (si ya se simuló)
        Map<String, Double> pesoPropagacion = new HashMap<>();
        if (simulacion != null) {
            for (SimuladorPropagacion.NodoComprometido nodo : simulacion.getNodosComprometidos()) {
                pesoPropagacion.put(nodo.getActivo().getIdActivo(), nodo.getProbAcumulada());
            }
        }

        // Filtrar acciones pendientes que caben individualmente en el presupuesto
        List<AccionMitigacion> candidatos = new ArrayList<>();
        for (AccionMitigacion a : acciones.values()) {
            if (!a.isAplicada() && a.getCostoEstimado() <= presupuestoMaximo) {
                candidatos.add(a);
            }
        }

        if (candidatos.isEmpty()) {
            return new PlanMitigacion(new ArrayList<>(), presupuestoMaximo, 0.0, 0.0, 0.0, 0.0);
        }

        int n = candidatos.size();
        // Si el presupuesto es muy grande, ajustamos una escala para que la matriz DP no ocupe demasiada memoria
        int capacidad = (int) Math.floor(presupuestoMaximo);
        double factorEscala = 1.0;
        if (capacidad > 10000) {
            factorEscala = presupuestoMaximo / 10000.0;
            capacidad = 10000;
        }

        int[] pesos = new int[n];
        double[] valores = new double[n];
        for (int i = 0; i < n; i++) {
            AccionMitigacion acc = candidatos.get(i);
            int pesoItem = (int) Math.ceil(acc.getCostoEstimado() / factorEscala);
            if (pesoItem < 1) {
                pesoItem = 1;
            }
            pesos[i] = pesoItem;

            double prob = 0.0;
            if (pesoPropagacion.containsKey(acc.getActivo().getIdActivo())) {
                prob = pesoPropagacion.get(acc.getActivo().getIdActivo());
            }
            double multiplicador = 1.0 + 0.25 * prob * acc.getActivo().calcularFactorCriticidad();
            valores[i] = acc.getReduccionRiesgo() * multiplicador;
        }

        // Llenado de la tabla dp[i][c]
        double[][] dp = new double[n + 1][capacidad + 1];
        for (int i = 1; i <= n; i++) {
            int w = pesos[i - 1];
            double v = valores[i - 1];
            for (int c = 0; c <= capacidad; c++) {
                dp[i][c] = dp[i - 1][c];
                if (w <= c) {
                    double opcionIncluir = dp[i - 1][c - w] + v;
                    if (opcionIncluir > dp[i][c]) {
                        dp[i][c] = opcionIncluir;
                    }
                }
            }
        }

        // Reconstrucción de las acciones elegidas
        List<AccionMitigacion> seleccionadas = new ArrayList<>();
        int cRestante = capacidad;
        for (int i = n; i >= 1; i--) {
            if (dp[i][cRestante] > dp[i - 1][cRestante] + 0.0001) {
                seleccionadas.add(candidatos.get(i - 1));
                cRestante -= pesos[i - 1];
            }
        }

        // Ordenar por mejor relación beneficio/costo (ordenamiento burbuja sencillo)
        for (int i = 0; i < seleccionadas.size() - 1; i++) {
            for (int j = 0; j < seleccionadas.size() - 1 - i; j++) {
                if (seleccionadas.get(j).calcularRatioCostoBeneficio()
                        < seleccionadas.get(j + 1).calcularRatioCostoBeneficio()) {
                    AccionMitigacion temp = seleccionadas.get(j);
                    seleccionadas.set(j, seleccionadas.get(j + 1));
                    seleccionadas.set(j + 1, temp);
                }
            }
        }

        double costoTotal = 0.0;
        double horasTotales = 0.0;
        double reduccionBase = 0.0;
        double reduccionPonderada = 0.0;
        for (AccionMitigacion a : seleccionadas) {
            costoTotal += a.getCostoEstimado();
            horasTotales += a.getHorasHombre();
            reduccionBase += a.getReduccionRiesgo();

            double prob = 0.0;
            if (pesoPropagacion.containsKey(a.getActivo().getIdActivo())) {
                prob = pesoPropagacion.get(a.getActivo().getIdActivo());
            }
            double multiplicador = 1.0 + 0.25 * prob * a.getActivo().calcularFactorCriticidad();
            reduccionPonderada += a.getReduccionRiesgo() * multiplicador;
        }

        return new PlanMitigacion(
                seleccionadas,
                presupuestoMaximo,
                Math.round(costoTotal * 100.0) / 100.0,
                Math.round(horasTotales * 10.0) / 10.0,
                Math.round(reduccionBase * 100.0) / 100.0,
                Math.round(reduccionPonderada * 100.0) / 100.0);
    }

    public int aplicarPlan(PlanMitigacion plan) {
        if (plan == null) {
            return 0;
        }
        int aplicados = 0;
        for (AccionMitigacion accion : plan.getAccionesSeleccionadas()) {
            if (!accion.isAplicada()) {
                accion.aplicarParche();
                aplicados++;
            }
        }
        return aplicados;
    }
}
