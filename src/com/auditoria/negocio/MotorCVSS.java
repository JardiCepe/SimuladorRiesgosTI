package com.auditoria.negocio;

import com.auditoria.modelo.ActivoRed;
import com.auditoria.modelo.PuertoServicio;
import com.auditoria.modelo.Vulnerabilidad;
import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class MotorCVSS {

    private final Map<String, Vulnerabilidad> catalogoCVE;

    public MotorCVSS() {
        this.catalogoCVE = new LinkedHashMap<>();
    }

    public void registrarVulnerabilidad(Vulnerabilidad vulnerabilidad) throws AuditoriaException {
        if (vulnerabilidad == null) {
            throw new AuditoriaException("La vulnerabilidad no puede ser nula.");
        }
        String codigo = vulnerabilidad.getCodigoCVE();
        if (catalogoCVE.containsKey(codigo)) {
            throw new AuditoriaException("El código " + codigo + " ya existe en el catálogo.");
        }
        catalogoCVE.put(codigo, vulnerabilidad);
    }

    public Vulnerabilidad buscarPorCVE(String codigoCVE) throws AuditoriaException {
        String normalizado = ValidadorDatos.validarCodigoCVE(codigoCVE);
        Vulnerabilidad v = catalogoCVE.get(normalizado);
        if (v == null) {
            throw new AuditoriaException("No se encontró la vulnerabilidad " + normalizado + " en el catálogo.");
        }
        return v;
    }

    public List<Vulnerabilidad> listarCatalogo() {
        return Collections.unmodifiableList(new ArrayList<>(catalogoCVE.values()));
    }

    public void actualizarVulnerabilidad(String codigoCVE, String descripcion, String soAfectado,
                                         int puertoAsociado, String vectorAtaque, double[] impactoCIA)
            throws AuditoriaException {
        Vulnerabilidad v = buscarPorCVE(codigoCVE);
        v.setDescripcion(descripcion);
        v.setSoAfectado(soAfectado);
        v.setPuertoAsociado(puertoAsociado);
        v.setVectorAtaque(vectorAtaque);
        v.setImpactoCIA(impactoCIA);
    }

    public Vulnerabilidad eliminarVulnerabilidad(String codigoCVE) throws AuditoriaException {
        Vulnerabilidad v = buscarPorCVE(codigoCVE);
        catalogoCVE.remove(v.getCodigoCVE());
        return v;
    }

    public String asociarVulnerabilidadAActivo(String codigoCVE, ActivoRed activo)
            throws AuditoriaException {
        if (activo == null) {
            throw new AuditoriaException("El activo destino no puede ser nulo.");
        }
        Vulnerabilidad v = buscarPorCVE(codigoCVE);
        activo.agregarVulnerabilidad(v);

        boolean coincideSO = activo.getSistemaOperativo().toLowerCase()
                .contains(v.getSoAfectado().toLowerCase())
                || v.getSoAfectado().equalsIgnoreCase("Multiplataforma")
                || v.getSoAfectado().equalsIgnoreCase("Todos");
        boolean coincidePuerto = v.getPuertoAsociado() == 0;
        for (PuertoServicio p : activo.getPuertos()) {
            if (p.getNumeroPuerto() == v.getPuertoAsociado()) {
                coincidePuerto = true;
                break;
            }
        }
        if (coincideSO && coincidePuerto) {
            return "Correlación exacta de SO y servicio/puerto confirmada.";
        }
        return "Asociada manualmente (nota: revise coincidencia de SO '"
                + v.getSoAfectado() + "' o puerto " + v.getPuertoAsociado() + ").";
    }

    public boolean desasociarVulnerabilidadDeActivo(String codigoCVE, ActivoRed activo)
            throws AuditoriaException {
        if (activo == null) {
            throw new AuditoriaException("El activo no puede ser nulo.");
        }
        String norm = ValidadorDatos.validarCodigoCVE(codigoCVE);
        return activo.removerVulnerabilidad(norm);
    }

    public double calcularSeveridadConsolidada(ActivoRed activo) throws AuditoriaException {
        if (activo == null) {
            throw new AuditoriaException("El activo no puede ser nulo.");
        }
        return activo.getPuntajeCVSS();
    }

    public String obtenerEtiquetaSeveridad(double puntaje) {
        if (puntaje <= 0.0) {
            return "Informativo";
        }
        if (puntaje < 4.0) {
            return "Bajo";
        }
        if (puntaje < 7.0) {
            return "Medio";
        }
        if (puntaje < 9.0) {
            return "Alto";
        }
        return "Crítico";
    }
}
