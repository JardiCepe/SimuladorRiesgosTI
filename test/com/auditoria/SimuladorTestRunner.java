package com.auditoria;

import com.auditoria.modelo.AccionMitigacion;
import com.auditoria.modelo.ActivoRed;
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
import com.auditoria.util.AuditoriaException;
import com.auditoria.util.DatosIniciales;
import com.auditoria.util.ValidadorDatos;

import java.time.LocalDate;
import java.util.List;

/**
 * Suite de pruebas unitarias y de integración en Java puro (sin dependencias externas).
 */
public class SimuladorTestRunner {

    private static int pruebasPasadas = 0;

    public static void main(String[] args) throws Exception {
        probarValidaciones();
        probarModulo1InventarioYExposicion();
        probarModulo2MotorCVSS();
        probarModulo3SimuladorPropagacionYCiclos();
        probarModulo4OptimizadorMochila();
        probarModulo5AuditoriaYFlujoPYME();

        System.out.println("====================================================");
        System.out.println("TODAS LAS PRUEBAS PASARON: " + pruebasPasadas + " / " + pruebasPasadas);
        System.out.println("====================================================");
    }

    private static void probarValidaciones() throws AuditoriaException {
        assertEquals("192.168.1.10", ValidadorDatos.validarIPv4("192.168.1.10"), "IPv4 válida");
        assertThrows(AuditoriaException.class, () -> ValidadorDatos.validarIPv4("256.1.1.1"), "IPv4 octeto >255");
        assertThrows(AuditoriaException.class, () -> ValidadorDatos.validarIPv4("192.168.1"), "IPv4 incompleta");
        assertThrows(AuditoriaException.class, () -> ValidadorDatos.validarPuerto(0), "Puerto 0 inválido");
        assertThrows(AuditoriaException.class, () -> ValidadorDatos.validarPuerto(65536), "Puerto >65535");
        assertEquals("CVE-2020-0796", ValidadorDatos.validarCodigoCVE("cve-2020-0796"), "CVE normalizado");
        assertThrows(AuditoriaException.class, () -> ValidadorDatos.validarCodigoCVE("CVE-20-12"), "CVE malformado");
        assertThrows(AuditoriaException.class, () -> ValidadorDatos.validarPositivo(0.0, "Presupuesto"), "Presupuesto 0");
        assertThrows(AuditoriaException.class, () -> ValidadorDatos.validarFechaISO("2026-99-99"), "Fecha inválida");
        pruebasPasadas++;
    }

    private static void probarModulo1InventarioYExposicion() throws AuditoriaException {
        GestorInventario inv = new GestorInventario();
        Servidor srv = new Servidor("SRV-1", "10.0.0.10", "db-01", "Ubuntu 22.04", "Base de Datos", true);
        srv.agregarPuerto(new PuertoServicio(443, "TCP", "HTTPS"));
        assertEquals("Baja", srv.getNivelExposicion(), "Solo 443 debe ser Baja");

        srv.agregarPuerto(new PuertoServicio(22, "TCP", "SSH"));
        assertEquals("Media", srv.getNivelExposicion(), "SSH debe elevar a Media");

        srv.agregarPuerto(new PuertoServicio(445, "TCP", "SMB"));
        assertEquals("Crítica", srv.getNivelExposicion(), "SMB 445 debe elevar a Crítica");

        inv.registrarActivo(srv);
        assertEquals(1.9, srv.calcularFactorCriticidad(), "Criticidad servidor BD con datos críticos");

        EstacionTrabajo ws = new EstacionTrabajo("WS-1", "10.0.0.20", "pc-01", "Windows 11", "Finanzas", true);
        ws.agregarPuerto(new PuertoServicio(80, "TCP", "HTTP"));
        inv.registrarActivo(ws);
        assertEquals(1.35, ws.calcularFactorCriticidad(), "WS con privilegios admin");

        DispositivoRed router = new DispositivoRed("NET-1", "10.0.0.1", "gw-01", "Cisco IOS", "Router", "17.3");
        router.agregarPuerto(new PuertoServicio(23, "TCP", "Telnet"));
        inv.registrarActivo(router);
        assertEquals("Crítica", router.getNivelExposicion(), "Telnet 23 debe ser Crítica");
        assertEquals(1.6, router.calcularFactorCriticidad(), "Router criticidad 1.6");

        // IP duplicada rechazada
        assertThrows(AuditoriaException.class,
                () -> inv.registrarActivo(new EstacionTrabajo("WS-2", "10.0.0.10", "dup", "Linux", "IT", false)),
                "Debe rechazar IP duplicada");

        // Alertas generadas
        List<String> alertas = inv.generarAlertasExposicion(srv);
        assertTrue(!alertas.isEmpty(), "Debe emitir alerta para puerto 445");
        pruebasPasadas++;
    }

    private static void probarModulo2MotorCVSS() throws AuditoriaException {
        MotorCVSS motor = new MotorCVSS();
        Vulnerabilidad info = new Vulnerabilidad(
                "CVE-2024-0001", "Informativa", "Linux", 0, "Local", new double[]{0.0, 0.0, 0.0});
        assertEquals(0.0, info.calcularScoreCVSS(), "CIA 0 debe dar 0.0");
        assertEquals("Informativo", info.obtenerEtiquetaSeveridad(), "Etiqueta Informativo");

        double[] ciaOriginal = {0.56, 0.56, 0.56};
        Vulnerabilidad crit = new Vulnerabilidad(
                "CVE-2020-0796", "SMBGhost", "Windows", 445, "Remoto", ciaOriginal);
        ciaOriginal[0] = 0.0; // comprobar copia defensiva
        assertTrue(crit.calcularScoreCVSS() >= 9.0, "SMBGhost remoto CIA alto debe ser >= 9.0");
        assertEquals("Crítico", crit.obtenerEtiquetaSeveridad(), "Etiqueta Crítico");

        motor.registrarVulnerabilidad(crit);
        Servidor srv = new Servidor("SRV-1", "10.0.0.5", "fs", "Windows Server 2019", "Archivos", true);
        srv.agregarPuerto(new PuertoServicio(445, "TCP", "SMB"));
        motor.asociarVulnerabilidadAActivo("CVE-2020-0796", srv);
        assertTrue(motor.calcularSeveridadConsolidada(srv) >= 9.0, "Severidad consolidada del servidor");
        pruebasPasadas++;
    }

    private static void probarModulo3SimuladorPropagacionYCiclos() throws AuditoriaException {
        GestorInventario inv = new GestorInventario();
        SimuladorPropagacion sim = new SimuladorPropagacion();

        EstacionTrabajo pc = new EstacionTrabajo("WS-1", "10.0.1.10", "pc-user", "Windows 10", "Ventas", true);
        pc.agregarPuerto(new PuertoServicio(445, "TCP", "SMB"));
        Servidor srvA = new Servidor("SRV-1", "10.0.1.20", "srv-a", "Windows 2019", "Archivos", true);
        srvA.agregarPuerto(new PuertoServicio(445, "TCP", "SMB"));
        Servidor srvSeguro = new Servidor("SRV-2", "10.0.1.30", "srv-seg", "Linux", "Backup", true);
        srvSeguro.agregarPuerto(new PuertoServicio(443, "TCP", "HTTPS"));

        Vulnerabilidad vCrit = new Vulnerabilidad(
                "CVE-2017-0144", "EternalBlue", "Windows", 445, "Remoto", new double[]{0.56, 0.56, 0.56});
        srvA.agregarVulnerabilidad(vCrit);

        inv.registrarActivo(pc);
        inv.registrarActivo(srvA);
        inv.registrarActivo(srvSeguro);

        // Ciclo entre WS-1 <-> SRV-1 y enlace inactivo hacia SRV-2
        sim.registrarEnlace(new EnlaceRed("L1", pc, srvA, "Troncal", true));
        sim.registrarEnlace(new EnlaceRed("L2", srvA, pc, "LAN", true));
        sim.registrarEnlace(new EnlaceRed("L3", srvA, srvSeguro, "LAN", false));

        double[][] matriz = sim.construirMatrizAdyacencia(inv.listarActivos());
        assertTrue(matriz[0][1] > 0.0, "Matriz debe reflejar enlace L1");
        assertEquals(0.0, matriz[1][2], "Enlace inactivo debe tener probabilidad 0.0");

        SimuladorPropagacion.ResultadoSimulacion res = sim.simularPropagacion(
                pc, "Ransomware", inv.listarActivos());
        assertEquals(2, res.getNodosComprometidos().size(), "Debe comprometer WS-1 y SRV-1, no SRV-2 inactivo");
        assertTrue(res.getPorcentajeRedAfectada() > 60.0 && res.getPorcentajeRedAfectada() < 70.0,
                "Porcentaje 2/3 ≈ 66.67%");
        pruebasPasadas++;
    }

    private static void probarModulo4OptimizadorMochila() throws AuditoriaException {
        OptimizadorMitigacion opt = new OptimizadorMitigacion();
        Servidor srv = new Servidor("SRV-1", "10.0.2.10", "srv-1", "Linux", "Web", true);
        srv.agregarPuerto(new PuertoServicio(8080, "TCP", "HTTP"));

        Vulnerabilidad v1 = new Vulnerabilidad("CVE-2021-0001", "V1", "Linux", 8080, "Remoto", new double[]{0.56, 0.56, 0.56});
        Vulnerabilidad v2 = new Vulnerabilidad("CVE-2021-0002", "V2", "Linux", 8080, "Remoto", new double[]{0.56, 0.22, 0.22});
        Vulnerabilidad v3 = new Vulnerabilidad("CVE-2021-0003", "V3", "Linux", 8080, "Local", new double[]{0.22, 0.22, 0.22});
        srv.agregarVulnerabilidad(v1);
        srv.agregarVulnerabilidad(v2);
        srv.agregarVulnerabilidad(v3);

        // Mochila clásica: presupuesto $500
        // A1: costo 350, red 10; A2: costo 250, red 8; A3: costo 250, red 7 -> óptimo A2+A3 = 15 (costo 500)
        opt.registrarAccion(new AccionMitigacion("M1", srv, v1, "Parche", 350.0, 4.0, 10.0));
        opt.registrarAccion(new AccionMitigacion("M2", srv, v2, "Parche", 250.0, 3.0, 8.0));
        opt.registrarAccion(new AccionMitigacion("M3", srv, v3, "Parche", 250.0, 2.0, 7.0));

        assertThrows(AuditoriaException.class,
                () -> opt.optimizarPlanMitigacion(-50.0, null),
                "Debe rechazar presupuesto negativo");

        OptimizadorMitigacion.PlanMitigacion plan = opt.optimizarPlanMitigacion(500.0, null);
        assertEquals(500.0, plan.getCostoTotal(), "Costo óptimo exacto 500");
        assertEquals(15.0, plan.getReduccionRiesgoTotal(), "Reducción óptima 15 (M2 + M3)");
        assertEquals(2, plan.getAccionesSeleccionadas().size(), "Debe seleccionar 2 acciones");

        int aplicados = opt.aplicarPlan(plan);
        assertEquals(2, aplicados, "Debe aplicar 2 parches");
        assertEquals(1, srv.getVulnerabilidades().size(), "Debe quedar solo v1 sin mitigar");
        pruebasPasadas++;
    }

    private static void probarModulo5AuditoriaYFlujoPYME() throws AuditoriaException {
        GestorInventario inv = new GestorInventario();
        MotorCVSS motor = new MotorCVSS();
        SimuladorPropagacion sim = new SimuladorPropagacion();
        OptimizadorMitigacion opt = new OptimizadorMitigacion();
        AuditoriaService aud = new AuditoriaService();

        DatosIniciales.cargarTopologiaPYME(inv, motor, sim, opt, aud);
        assertEquals(6, inv.cantidadActivos(), "PYME debe tener 6 activos");
        assertEquals(5, motor.listarCatalogo().size(), "PYME debe tener 5 CVEs");
        assertEquals(7, sim.listarEnlaces().size(), "PYME debe tener 7 enlaces");
        assertEquals(7, opt.listarAcciones().size(), "PYME debe tener 7 mitigaciones");

        ActivoRed pacienteCero = inv.buscarActivoPorId("WS-01");
        SimuladorPropagacion.ResultadoSimulacion simRes =
                sim.simularPropagacion(pacienteCero, "Ransomware", inv.listarActivos());
        assertTrue(simRes.getNodosComprometidos().size() >= 2, "Debe propagarse desde WS-01");

        ReporteAuditoria repInicial = aud.ejecutarAuditoria(null, inv, opt, sim);
        double scoreInicial = repInicial.getScoreGlobal();
        assertTrue(!repInicial.listarBrechasPendientes().isEmpty(), "Debe detectar brechas iniciales");
        assertTrue(!"Aceptable".equals(repInicial.getDictamen()), "Estado inicial no debe ser Aceptable");

        // Mitigar con presupuesto amplio y volver a auditar
        OptimizadorMitigacion.PlanMitigacion plan = opt.optimizarPlanMitigacion(5000.0, simRes);
        opt.aplicarPlan(plan);
        ReporteAuditoria repPost = aud.ejecutarAuditoria(null, inv, opt, sim);
        assertTrue(repPost.getScoreGlobal() > scoreInicial, "El score global debe mejorar tras mitigar");
        pruebasPasadas++;
    }

    private static void assertTrue(boolean condicion, String msg) {
        if (!condicion) {
            throw new AssertionError("Fallo en aserción: " + msg);
        }
    }

    private static void assertEquals(Object esperado, Object actual, String msg) {
        if (esperado == null ? actual != null : !esperado.equals(actual)) {
            throw new AssertionError("Fallo en '" + msg + "': esperado=" + esperado + ", actual=" + actual);
        }
    }

    private static void assertEquals(double esperado, double actual, String msg) {
        if (Math.abs(esperado - actual) > 1e-6) {
            throw new AssertionError("Fallo en '" + msg + "': esperado=" + esperado + ", actual=" + actual);
        }
    }

    private static void assertThrows(Class<? extends Throwable> tipoEsperado, RunnableConExcepcion accion, String msg) {
        try {
            accion.run();
        } catch (Throwable t) {
            if (tipoEsperado.isInstance(t)) {
                return;
            }
            throw new AssertionError("Excepción incorrecta en '" + msg + "': " + t.getClass().getName());
        }
        throw new AssertionError("Se esperaba excepción " + tipoEsperado.getSimpleName() + " en: " + msg);
    }

    @FunctionalInterface
    private interface RunnableConExcepcion {
        void run() throws Exception;
    }
}
