package com.auditoria.negocio;

import com.auditoria.modelo.ActivoRed;
import com.auditoria.modelo.PuertoServicio;
import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class GestorInventario {

    private final Map<String, ActivoRed> activos;

    public GestorInventario() {
        this.activos = new LinkedHashMap<>();
    }

    public void registrarActivo(ActivoRed activo) throws AuditoriaException {
        if (activo == null) {
            throw new AuditoriaException("El activo a registrar no puede ser nulo.");
        }
        String id = activo.getIdActivo();
        if (activos.containsKey(id)) {
            throw new AuditoriaException("Ya existe un activo registrado con el ID: " + id);
        }
        for (ActivoRed existente : activos.values()) {
            if (existente.getDireccionIP().equals(activo.getDireccionIP())) {
                throw new AuditoriaException(
                        "La dirección IP " + activo.getDireccionIP()
                                + " ya está asignada al activo " + existente.getIdActivo() + ".");
            }
        }
        activos.put(id, activo);
    }

    public ActivoRed buscarActivoPorId(String idActivo) throws AuditoriaException {
        String idNorm = ValidadorDatos.validarTextoNoVacio(idActivo, "ID de Activo").toUpperCase();
        ActivoRed encontrado = activos.get(idNorm);
        if (encontrado == null) {
            throw new AuditoriaException("No se encontró ningún activo con ID: " + idNorm);
        }
        return encontrado;
    }

    public List<ActivoRed> listarActivos() {
        return new ArrayList<>(activos.values());
    }

    public void actualizarActivo(String idActivo, String nuevaIP, String nuevoHost, String nuevoSO)
            throws AuditoriaException {
        ActivoRed activo = buscarActivoPorId(idActivo);
        String ipValidada = ValidadorDatos.validarIPv4(nuevaIP);
        for (ActivoRed otro : activos.values()) {
            if (!otro.getIdActivo().equals(activo.getIdActivo())
                    && otro.getDireccionIP().equals(ipValidada)) {
                throw new AuditoriaException(
                        "La IP " + ipValidada + " ya está en uso por el activo " + otro.getIdActivo() + ".");
            }
        }
        activo.setDireccionIP(ipValidada);
        activo.setHostname(nuevoHost);
        activo.setSistemaOperativo(nuevoSO);
    }

    public ActivoRed eliminarActivo(String idActivo) throws AuditoriaException {
        ActivoRed activo = buscarActivoPorId(idActivo);
        activos.remove(activo.getIdActivo());
        return activo;
    }

    public List<String> agregarPuertoAActivo(String idActivo, PuertoServicio puerto)
            throws AuditoriaException {
        ActivoRed activo = buscarActivoPorId(idActivo);
        activo.agregarPuerto(puerto);
        return generarAlertasExposicion(activo);
    }

    public boolean removerPuertoDeActivo(String idActivo, int numeroPuerto, String protocolo)
            throws AuditoriaException {
        ActivoRed activo = buscarActivoPorId(idActivo);
        return activo.removerPuerto(numeroPuerto, protocolo);
    }

    public List<String> generarAlertasExposicion(ActivoRed activo) throws AuditoriaException {
        if (activo == null) {
            throw new AuditoriaException("El activo no puede ser nulo.");
        }
        String nivel = activo.evaluarExposicion();
        List<String> alertas = new ArrayList<>();
        for (PuertoServicio p : activo.getPuertos()) {
            if (p.verificarRiesgoPuerto()) {
                alertas.add(String.format(
                        "ALERTA [%s] %s (%s): Puerto inseguro %d/%s (%s) habilitado.",
                        nivel.toUpperCase(), activo.getIdActivo(), activo.getHostname(),
                        p.getNumeroPuerto(), p.getProtocolo(), p.getServicio()));
            }
        }
        return alertas;
    }

    public int cantidadActivos() {
        return activos.size();
    }
}
