package com.auditoria.modelo;

import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

public class Servidor extends ActivoRed {

    private String rolServidor;
    private boolean datosCriticos;

    public Servidor(String idActivo, String direccionIP, String hostname,
                    String sistemaOperativo, String rolServidor, boolean datosCriticos)
            throws AuditoriaException {
        super(idActivo, direccionIP, hostname, sistemaOperativo);
        setRolServidor(rolServidor);
        this.datosCriticos = datosCriticos;
    }

    @Override
    public double calcularFactorCriticidad() {
        double factor = 1.3;
        if (datosCriticos) {
            factor += 0.4;
        }
        String rolLower = rolServidor.toLowerCase();
        if (rolLower.contains("base de datos") || rolLower.contains("dominio") || rolLower.contains("erp")) {
            factor += 0.2;
        }
        return Math.round(factor * 100.0) / 100.0;
    }

    @Override
    public String getTipoActivo() {
        return "Servidor";
    }

    public String getRolServidor() {
        return rolServidor;
    }

    public void setRolServidor(String rolServidor) throws AuditoriaException {
        this.rolServidor = ValidadorDatos.validarTextoNoVacio(rolServidor, "Rol del servidor");
    }

    public boolean isDatosCriticos() {
        return datosCriticos;
    }

    public void setDatosCriticos(boolean datosCriticos) {
        this.datosCriticos = datosCriticos;
    }
}
