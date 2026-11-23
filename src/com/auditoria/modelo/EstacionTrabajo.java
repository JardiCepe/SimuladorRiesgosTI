package com.auditoria.modelo;

import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

public class EstacionTrabajo extends ActivoRed {

    private String departamento;
    private boolean privilegiosAdmin;

    public EstacionTrabajo(String idActivo, String direccionIP, String hostname,
                           String sistemaOperativo, String departamento, boolean privilegiosAdmin)
            throws AuditoriaException {
        super(idActivo, direccionIP, hostname, sistemaOperativo);
        setDepartamento(departamento);
        this.privilegiosAdmin = privilegiosAdmin;
    }

    @Override
    public double calcularFactorCriticidad() {
        double factor = 1.0;
        if (privilegiosAdmin) {
            factor += 0.35;
        }
        return Math.round(factor * 100.0) / 100.0;
    }

    @Override
    public String getTipoActivo() {
        return "Estación de Trabajo";
    }

    public String getDepartamento() {
        return departamento;
    }

    public void setDepartamento(String departamento) throws AuditoriaException {
        this.departamento = ValidadorDatos.validarTextoNoVacio(departamento, "Departamento");
    }

    public boolean isPrivilegiosAdmin() {
        return privilegiosAdmin;
    }

    public void setPrivilegiosAdmin(boolean privilegiosAdmin) {
        this.privilegiosAdmin = privilegiosAdmin;
    }
}
