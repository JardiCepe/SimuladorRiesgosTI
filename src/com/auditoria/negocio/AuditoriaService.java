package com.auditoria.negocio;

import com.auditoria.modelo.AccionMitigacion;
import com.auditoria.modelo.ActivoRed;
import com.auditoria.modelo.PuertoServicio;
import com.auditoria.modelo.ReporteAuditoria;
import com.auditoria.modelo.Vulnerabilidad;
import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class AuditoriaService {

    private final Map<String, ReporteAuditoria> perfiles;
    private String idPerfilActivo;

    public AuditoriaService() {
        this.perfiles = new LinkedHashMap<>();
    }

    public void registrarPerfil(ReporteAuditoria perfil) throws AuditoriaException {
        if (perfil == null) {
            throw new AuditoriaException("El perfil de auditoría no puede ser nulo.");
        }
        String id = perfil.getIdAuditoria();
        if (perfiles.containsKey(id)) {
            throw new AuditoriaException("Ya existe un perfil de auditoría con ID: " + id);
        }
        perfiles.put(id, perfil);
        if (idPerfilActivo == null) {
            idPerfilActivo = id;
        }
    }

    public ReporteAuditoria buscarPerfilPorId(String idAuditoria) throws AuditoriaException {
        String idNorm = ValidadorDatos.validarTextoNoVacio(idAuditoria, "ID de Auditoría").toUpperCase();
        ReporteAuditoria perfil = perfiles.get(idNorm);
        if (perfil == null) {
            throw new AuditoriaException("No se encontró el perfil de auditoría: " + idNorm);
        }
        return perfil;
    }

    public List<ReporteAuditoria> listarPerfiles() {
        return new ArrayList<>(perfiles.values());
    }

    public void actualizarPerfil(String idAuditoria, double nuevoUmbral,
                                 double nuevaCobertura, LocalDate nuevaFecha) throws AuditoriaException {
        ReporteAuditoria perfil = buscarPerfilPorId(idAuditoria);
        perfil.setUmbralTolerancia(nuevoUmbral);
        perfil.setPorcentajeCoberturaExigido(nuevaCobertura);
        perfil.setFechaValidez(nuevaFecha);
    }

    public ReporteAuditoria eliminarPerfil(String idAuditoria) throws AuditoriaException {
        ReporteAuditoria perfil = buscarPerfilPorId(idAuditoria);
        perfiles.remove(perfil.getIdAuditoria());
        if (perfil.getIdAuditoria().equals(idPerfilActivo)) {
            idPerfilActivo = perfiles.isEmpty() ? null : perfiles.keySet().iterator().next();
        }
        return perfil;
    }

    public void seleccionarPerfilActivo(String idAuditoria) throws AuditoriaException {
        ReporteAuditoria perfil = buscarPerfilPorId(idAuditoria);
        this.idPerfilActivo = perfil.getIdAuditoria();
    }

    public ReporteAuditoria getPerfilActivo() throws AuditoriaException {
        if (idPerfilActivo == null || !perfiles.containsKey(idPerfilActivo)) {
            throw new AuditoriaException("No hay ningún perfil de auditoría configurado.");
        }
        return perfiles.get(idPerfilActivo);
    }

    // Evalúa los activos, acciones de mitigación y última simulación frente al perfil normativo
    public ReporteAuditoria ejecutarAuditoria(String idAuditoria,
                                                GestorInventario inventario,
                                                OptimizadorMitigacion optimizador,
                                                SimuladorPropagacion simulador)
            throws AuditoriaException {
        ReporteAuditoria reporte;
        if (idAuditoria == null || idAuditoria.trim().isEmpty()) {
            reporte = getPerfilActivo();
        } else {
            reporte = buscarPerfilPorId(idAuditoria);
        }

        List<ActivoRed> activos = inventario.listarActivos();
        if (activos.isEmpty()) {
            throw new AuditoriaException("No hay activos registrados en el inventario para auditar.");
        }

        List<String> brechas = new ArrayList<>();
        double sumaPonderadaCVSS = 0.0;
        double sumaCriticidad = 0.0;
        int activosSinExposicionCritica = 0;

        for (ActivoRed activo : activos) {
            double cvss = activo.getPuntajeCVSS();
            double crit = activo.calcularFactorCriticidad();
            sumaPonderadaCVSS += cvss * crit;
            sumaCriticidad += crit;

            if (cvss > reporte.getUmbralTolerancia()) {
                brechas.add(String.format(
                        "[CVSS] %s (%s) supera el umbral %.1f con puntaje %.1f.",
                        activo.getIdActivo(), activo.getHostname(),
                        reporte.getUmbralTolerancia(), cvss));
            }

            if (!"Crítica".equals(activo.getNivelExposicion())) {
                activosSinExposicionCritica++;
            }

            for (PuertoServicio p : activo.getPuertos()) {
                if (p.verificarRiesgoPuerto()) {
                    brechas.add(String.format(
                            "[PUERTO INSEGURO] %s (%s) expone %d/%s (%s).",
                            activo.getIdActivo(), activo.getHostname(),
                            p.getNumeroPuerto(), p.getProtocolo(), p.getServicio()));
                }
            }

            for (Vulnerabilidad v : activo.getVulnerabilidades()) {
                if (v.calcularScoreCVSS() >= 7.0) {
                    brechas.add(String.format(
                            "[CVE PENDIENTE] %s en %s (%s): CVSS %.1f (%s).",
                            v.getCodigoCVE(), activo.getIdActivo(), activo.getHostname(),
                            v.getPuntajeCVSS(), v.obtenerEtiquetaSeveridad()));
                }
            }
        }

        List<AccionMitigacion> todasAcciones = optimizador.listarAcciones();
        int accionesAplicadas = 0;
        for (AccionMitigacion a : todasAcciones) {
            if (a.isAplicada()) {
                accionesAplicadas++;
            }
        }

        double coberturaActual;
        if (todasAcciones.isEmpty()) {
            coberturaActual = brechas.isEmpty() ? 100.0 : 0.0;
        } else {
            coberturaActual = (accionesAplicadas * 100.0) / todasAcciones.size();
        }

        if (coberturaActual + 0.0001 < reporte.getPorcentajeCoberturaExigido()) {
            brechas.add(String.format(
                    "[COBERTURA] Cobertura de mitigación actual %.1f%% es inferior al %.1f%% exigido.",
                    coberturaActual, reporte.getPorcentajeCoberturaExigido()));
        }

        if (LocalDate.now().isAfter(reporte.getFechaValidez())) {
            brechas.add(String.format(
                    "[VIGENCIA] Perfil de auditoría vencido el %s.",
                    reporte.getFechaValidez()));
        }

        double cvssPromedio = sumaCriticidad > 0 ? sumaPonderadaCVSS / sumaCriticidad : 0.0;
        double componenteRiesgo = Math.max(0.0, 1.0 - (cvssPromedio / 10.0)) * 60.0;
        double componenteCobertura = (coberturaActual / 100.0) * 25.0;
        double componenteExposicion = ((double) activosSinExposicionCritica / activos.size()) * 15.0;

        double penalizacionPropagacion = 0.0;
        if (simulador != null && simulador.getUltimaSimulacion() != null) {
            double pctAfectado = simulador.getUltimaSimulacion().getPorcentajeRedAfectada();
            if (pctAfectado > 50.0) {
                penalizacionPropagacion = 5.0;
                brechas.add(String.format(
                        "[PROPAGACIÓN] Última simulación desde %s comprometió el %.1f%% de la red.",
                        simulador.getUltimaSimulacion().getPacienteCero().getIdActivo(), pctAfectado));
            }
        }

        double scoreGlobal = componenteRiesgo + componenteCobertura + componenteExposicion - penalizacionPropagacion;
        if (scoreGlobal < 0.0) {
            scoreGlobal = 0.0;
        }
        if (scoreGlobal > 100.0) {
            scoreGlobal = 100.0;
        }
        scoreGlobal = Math.round(scoreGlobal * 100.0) / 100.0;

        reporte.actualizarResultados(scoreGlobal, brechas);
        return reporte;
    }
}
