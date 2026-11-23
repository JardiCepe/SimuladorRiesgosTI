package com.auditoria.util;

import com.auditoria.modelo.AccionMitigacion;
import com.auditoria.modelo.DispositivoRed;
import com.auditoria.modelo.EnlaceRed;
import com.auditoria.modelo.EstacionTrabajo;
import com.auditoria.modelo.PuertoServicio;
import com.auditoria.modelo.ReporteAuditoria;
import com.auditoria.modelo.Servidor;
import com.auditoria.modelo.Vulnerabilidad;
import com.auditoria.negocio.AuditoriaService;
import com.auditoria.negocio.GestorInventario;
import com.auditoria.negocio.MotorCVSS;
import com.auditoria.negocio.OptimizadorMitigacion;
import com.auditoria.negocio.SimuladorPropagacion;

import java.time.LocalDate;

public final class DatosIniciales {

    private DatosIniciales() {
    }

    public static void cargarTopologiaPYME(GestorInventario inventario,
                                           MotorCVSS motorCVSS,
                                           SimuladorPropagacion simulador,
                                           OptimizadorMitigacion optimizador,
                                           AuditoriaService auditoria) throws AuditoriaException {

        // 1. Activos de red (6 nodos PYME)
        DispositivoRed routerBorde = new DispositivoRed(
                "NET-01", "192.168.1.1", "gw-borde-pyme", "Cisco IOS XE 17.3", "Router", "17.3.4");
        routerBorde.agregarPuerto(new PuertoServicio(22, "TCP", "SSH"));
        routerBorde.agregarPuerto(new PuertoServicio(23, "TCP", "Telnet"));
        routerBorde.agregarPuerto(new PuertoServicio(443, "TCP", "HTTPS-Mgmt"));

        DispositivoRed switchCore = new DispositivoRed(
                "NET-02", "192.168.1.2", "sw-core-oficina", "SwitchOS 2.13", "Switch", "2.13");
        switchCore.agregarPuerto(new PuertoServicio(22, "TCP", "SSH"));
        switchCore.agregarPuerto(new PuertoServicio(80, "TCP", "HTTP"));

        Servidor srvArchivos = new Servidor(
                "SRV-01", "192.168.1.10", "fs-archivos-01", "Windows Server 2019", "Archivos / SMB", true);
        srvArchivos.agregarPuerto(new PuertoServicio(21, "TCP", "FTP"));
        srvArchivos.agregarPuerto(new PuertoServicio(445, "TCP", "SMB"));
        srvArchivos.agregarPuerto(new PuertoServicio(3389, "TCP", "RDP"));

        Servidor srvBaseDatos = new Servidor(
                "SRV-02", "192.168.1.20", "db-erp-central", "Ubuntu Server 22.04", "Base de Datos ERP", true);
        srvBaseDatos.agregarPuerto(new PuertoServicio(22, "TCP", "SSH"));
        srvBaseDatos.agregarPuerto(new PuertoServicio(3306, "TCP", "MySQL"));
        srvBaseDatos.agregarPuerto(new PuertoServicio(8080, "TCP", "HTTP-API"));

        EstacionTrabajo pcContabilidad = new EstacionTrabajo(
                "WS-01", "192.168.1.51", "pc-contabilidad", "Windows 10 Pro", "Contabilidad", true);
        pcContabilidad.agregarPuerto(new PuertoServicio(445, "TCP", "SMB"));
        pcContabilidad.agregarPuerto(new PuertoServicio(139, "TCP", "NetBIOS"));

        EstacionTrabajo pcVentas = new EstacionTrabajo(
                "WS-02", "192.168.1.52", "pc-ventas", "Windows 11 Pro", "Comercial", false);
        pcVentas.agregarPuerto(new PuertoServicio(80, "TCP", "HTTP"));

        inventario.registrarActivo(routerBorde);
        inventario.registrarActivo(switchCore);
        inventario.registrarActivo(srvArchivos);
        inventario.registrarActivo(srvBaseDatos);
        inventario.registrarActivo(pcContabilidad);
        inventario.registrarActivo(pcVentas);

        // 2. Catálogo CVE real y asociaciones
        Vulnerabilidad cveSmbGhost = new Vulnerabilidad(
                "CVE-2020-0796",
                "SMBGhost - Ejecución remota de código en SMBv3",
                "Windows",
                445,
                "Remoto",
                new double[]{0.56, 0.56, 0.56});

        Vulnerabilidad cveEternalBlue = new Vulnerabilidad(
                "CVE-2017-0144",
                "EternalBlue - Desbordamiento remoto en SMBv1",
                "Windows",
                445,
                "Remoto",
                new double[]{0.56, 0.56, 0.22});

        Vulnerabilidad cveCiscoWeb = new Vulnerabilidad(
                "CVE-2023-20198",
                "Escalada de privilegios en Web UI de Cisco IOS XE",
                "Cisco IOS",
                443,
                "Remoto",
                new double[]{0.56, 0.56, 0.56});

        Vulnerabilidad cveLog4Shell = new Vulnerabilidad(
                "CVE-2021-44228",
                "Log4Shell - Inyección JNDI remota en servicios Java",
                "Ubuntu",
                8080,
                "Remoto",
                new double[]{0.56, 0.56, 0.56});

        Vulnerabilidad cveSshRegre = new Vulnerabilidad(
                "CVE-2024-6387",
                "regreSSHion - Condición de carrera en OpenSSH",
                "Ubuntu",
                22,
                "Local",
                new double[]{0.56, 0.22, 0.22});

        motorCVSS.registrarVulnerabilidad(cveSmbGhost);
        motorCVSS.registrarVulnerabilidad(cveEternalBlue);
        motorCVSS.registrarVulnerabilidad(cveCiscoWeb);
        motorCVSS.registrarVulnerabilidad(cveLog4Shell);
        motorCVSS.registrarVulnerabilidad(cveSshRegre);

        motorCVSS.asociarVulnerabilidadAActivo("CVE-2023-20198", routerBorde);
        motorCVSS.asociarVulnerabilidadAActivo("CVE-2020-0796", srvArchivos);
        motorCVSS.asociarVulnerabilidadAActivo("CVE-2017-0144", srvArchivos);
        motorCVSS.asociarVulnerabilidadAActivo("CVE-2021-44228", srvBaseDatos);
        motorCVSS.asociarVulnerabilidadAActivo("CVE-2024-6387", srvBaseDatos);
        motorCVSS.asociarVulnerabilidadAActivo("CVE-2020-0796", pcContabilidad);
        motorCVSS.asociarVulnerabilidadAActivo("CVE-2017-0144", pcContabilidad);

        // 3. Topología de enlaces dirigidos
        simulador.registrarEnlace(new EnlaceRed("LNK-01", routerBorde, switchCore, "Troncal", true));
        simulador.registrarEnlace(new EnlaceRed("LNK-02", switchCore, srvArchivos, "Troncal", true));
        simulador.registrarEnlace(new EnlaceRed("LNK-03", switchCore, srvBaseDatos, "Troncal", true));
        simulador.registrarEnlace(new EnlaceRed("LNK-04", switchCore, pcContabilidad, "LAN", true));
        simulador.registrarEnlace(new EnlaceRed("LNK-05", switchCore, pcVentas, "WLAN", true));
        simulador.registrarEnlace(new EnlaceRed("LNK-06", pcContabilidad, srvArchivos, "LAN", true));
        simulador.registrarEnlace(new EnlaceRed("LNK-07", srvArchivos, srvBaseDatos, "LAN", true));

        // 4. Acciones de mitigación y costos
        optimizador.registrarAccion(new AccionMitigacion(
                "MIT-01", routerBorde, cveCiscoWeb, "Actualización de parche", 320.0, 4.0, 9.5));
        optimizador.registrarAccion(new AccionMitigacion(
                "MIT-02", srvArchivos, cveSmbGhost, "Actualización de parche", 450.0, 6.0, 12.0));
        optimizador.registrarAccion(new AccionMitigacion(
                "MIT-03", srvArchivos, cveEternalBlue, "Reconfiguración de puerto", 180.0, 3.0, 8.5));
        optimizador.registrarAccion(new AccionMitigacion(
                "MIT-04", srvBaseDatos, cveLog4Shell, "Actualización de parche", 600.0, 8.0, 14.0));
        optimizador.registrarAccion(new AccionMitigacion(
                "MIT-05", srvBaseDatos, cveSshRegre, "Actualización de parche", 240.0, 3.5, 5.5));
        optimizador.registrarAccion(new AccionMitigacion(
                "MIT-06", pcContabilidad, cveSmbGhost, "Reemplazo de SO", 950.0, 12.0, 11.0));
        optimizador.registrarAccion(new AccionMitigacion(
                "MIT-07", pcContabilidad, cveEternalBlue, "Reconfiguración de puerto", 150.0, 2.0, 7.5));

        // 5. Perfil normativo de auditoría por defecto
        auditoria.registrarPerfil(new ReporteAuditoria(
                "AUD-PYME-2026", 5.0, 70.0, LocalDate.of(2027, 12, 31)));
    }
}
