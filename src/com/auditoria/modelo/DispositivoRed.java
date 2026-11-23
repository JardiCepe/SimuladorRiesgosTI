package com.auditoria.modelo;

import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

public class DispositivoRed extends ActivoRed {

    private String tipoEquipo;
    private String firmwareVersion;

    public DispositivoRed(String idActivo, String direccionIP, String hostname,
                          String sistemaOperativo, String tipoEquipo, String firmwareVersion)
            throws AuditoriaException {
        super(idActivo, direccionIP, hostname, sistemaOperativo);
        setTipoEquipo(tipoEquipo);
        setFirmwareVersion(firmwareVersion);
    }

    @Override
    public double calcularFactorCriticidad() {
        return "Router".equalsIgnoreCase(tipoEquipo) ? 1.6 : 1.4;
    }

    @Override
    public String getTipoActivo() {
        return "Dispositivo de Red (" + tipoEquipo + ")";
    }

    public String getTipoEquipo() {
        return tipoEquipo;
    }

    public void setTipoEquipo(String tipoEquipo) throws AuditoriaException {
        this.tipoEquipo = ValidadorDatos.validarTipoEquipoRed(tipoEquipo);
    }

    public String getFirmwareVersion() {
        return firmwareVersion;
    }

    public void setFirmwareVersion(String firmwareVersion) throws AuditoriaException {
        this.firmwareVersion = ValidadorDatos.validarTextoNoVacio(firmwareVersion, "Versión de firmware");
    }
}
