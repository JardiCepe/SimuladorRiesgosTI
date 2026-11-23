package com.auditoria.interfaz;

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
import java.util.Scanner;

public class MenuConsola {

    private final Scanner scanner;
    private final GestorInventario inventario;
    private final MotorCVSS motorCVSS;
    private final SimuladorPropagacion simulador;
    private final OptimizadorMitigacion optimizador;
    private final AuditoriaService auditoria;
    private OptimizadorMitigacion.PlanMitigacion ultimoPlan;

    public MenuConsola(GestorInventario inventario,
                       MotorCVSS motorCVSS,
                       SimuladorPropagacion simulador,
                       OptimizadorMitigacion optimizador,
                       AuditoriaService auditoria) {
        this.scanner = new Scanner(System.in);
        this.inventario = inventario;
        this.motorCVSS = motorCVSS;
        this.simulador = simulador;
        this.optimizador = optimizador;
        this.auditoria = auditoria;
    }

    public void iniciar() {
        imprimirEncabezado();
        boolean continuar = true;
        while (continuar) {
            System.out.println("\n==================== MENÚ PRINCIPAL ====================");
            System.out.println("1. Módulo 1 - Mapeo e Inventario de Activos y Puertos (Egas Kevin)");
            System.out.println("2. Módulo 2 - Catálogo de Vulnerabilidades y CVSS (Cáseres Jardi)");
            System.out.println("3. Módulo 3 - Topología y Simulación de Propagación (Albiño Alexis)");
            System.out.println("4. Módulo 4 - Plan de Mitigación y Presupuesto (Fiallos Christian)");
            System.out.println("5. Módulo 5 - Reportes de Cumplimiento y Auditoría (Yunga César)");
            System.out.println("6. Resumen Ejecutivo de Infraestructura");
            System.out.println("7. Recargar Datos Iniciales de Demostración (PYME)");
            System.out.println("0. Salir");
            int opcion = leerEnteroEnRango("Seleccione una opción: ", 0, 7);

            switch (opcion) {
                case 1 -> menuModulo1();
                case 2 -> menuModulo2();
                case 3 -> menuModulo3();
                case 4 -> menuModulo4();
                case 5 -> menuModulo5();
                case 6 -> mostrarResumenEjecutivo();
                case 7 -> recargarDemo();
                case 0 -> {
                    System.out.println("\nCerrando simulador. ¡Hasta pronto!");
                    continuar = false;
                }
                default -> System.out.println("Opción no válida.");
            }
        }
    }

    private void imprimirEncabezado() {
        System.out.println("========================================================================");
        System.out.println("  SIMULADOR DE EVALUACIÓN DE RIESGOS Y AUDITORÍA DE CIBERSEGURIDAD TI");
        System.out.println("  Entregable N° 2 - Arquitectura POO (Modo Consola)");
        System.out.println("========================================================================");
        System.out.printf("  Activos cargados: %d | CVEs en catálogo: %d | Enlaces: %d | Mitigaciones: %d%n",
                inventario.cantidadActivos(),
                motorCVSS.listarCatalogo().size(),
                simulador.listarEnlaces().size(),
                optimizador.listarAcciones().size());
    }

    private void menuModulo1() {
        boolean volver = false;
        while (!volver) {
            System.out.println("\n--- MÓDULO 1: INVENTARIO DE ACTIVOS Y PUERTOS ---");
            System.out.println("1. Listar activos de red");
            System.out.println("2. Registrar nuevo activo");
            System.out.println("3. Consultar detalle de un activo");
            System.out.println("4. Actualizar datos de un activo");
            System.out.println("5. Eliminar activo");
            System.out.println("6. Agregar puerto a un activo");
            System.out.println("7. Remover puerto de un activo");
            System.out.println("8. Analizar exposición perimetral y alertas");
            System.out.println("0. Volver al menú principal");
            int op = leerEnteroEnRango("Opción: ", 0, 8);

            switch (op) {
                case 1 -> listarActivosTabla();
                case 2 -> registrarActivoConsola();
                case 3 -> consultarDetalleActivo();
                case 4 -> actualizarActivoConsola();
                case 5 -> eliminarActivoConsola();
                case 6 -> agregarPuertoConsola();
                case 7 -> removerPuertoConsola();
                case 8 -> mostrarAlertasExposicion();
                case 0 -> volver = true;
                default -> System.out.println("Opción inválida.");
            }
        }
    }

    private void listarActivosTabla() {
        List<ActivoRed> activos = inventario.listarActivos();
        if (activos.isEmpty()) {
            System.out.println("No hay activos registrados.");
            return;
        }
        System.out.println("\n---------------------------------------------------------------------------------------------------");
        System.out.printf("%-8s %-16s %-18s %-24s %-20s %-10s %-6s%n",
                "ID", "IPv4", "Hostname", "Tipo", "Sistema Operativo", "Exposición", "CVSS");
        System.out.println("---------------------------------------------------------------------------------------------------");
        for (ActivoRed a : activos) {
            System.out.printf("%-8s %-16s %-18s %-24s %-20s %-10s %-6.1f%n",
                    a.getIdActivo(), a.getDireccionIP(), recortar(a.getHostname(), 18),
                    recortar(a.getTipoActivo(), 24), recortar(a.getSistemaOperativo(), 20),
                    a.getNivelExposicion(), a.getPuntajeCVSS());
        }
        System.out.println("---------------------------------------------------------------------------------------------------");
    }

    private void registrarActivoConsola() {
        System.out.println("\nTipo de activo: 1) Servidor  2) Estación de Trabajo  3) Dispositivo de Red");
        int tipo = leerEnteroEnRango("Seleccione tipo: ", 1, 3);

        while (true) {
            try {
                String id = leerTextoNoVacio("ID único (ej. SRV-03): ");
                String ip = leerIPv4("Dirección IPv4: ");
                String host = leerTextoNoVacio("Hostname: ");
                String so = leerTextoNoVacio("Sistema Operativo: ");

                ActivoRed nuevo;
                if (tipo == 1) {
                    String rol = leerTextoNoVacio("Rol del servidor (ej. Web, Base de Datos): ");
                    boolean crit = leerSiNo("¿Almacena datos críticos?");
                    nuevo = new Servidor(id, ip, host, so, rol, crit);
                } else if (tipo == 2) {
                    String depto = leerTextoNoVacio("Departamento: ");
                    boolean admin = leerSiNo("¿Tiene privilegios administrativos locales?");
                    nuevo = new EstacionTrabajo(id, ip, host, so, depto, admin);
                } else {
                    String equipo = leerTipoEquipo("Tipo de equipo (Router/Switch): ");
                    String fw = leerTextoNoVacio("Versión de firmware: ");
                    nuevo = new DispositivoRed(id, ip, host, so, equipo, fw);
                }

                System.out.println("Registre al menos un puerto abierto inicial (composición 1..*):");
                PuertoServicio puertoInicial = leerPuertoServicio();
                nuevo.agregarPuerto(puertoInicial);
                inventario.registrarActivo(nuevo);
                System.out.println("Activo registrado correctamente: " + nuevo);
                List<String> alertas = inventario.generarAlertasExposicion(nuevo);
                alertas.forEach(System.out::println);
                break;
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
                if (!leerSiNo("¿Desea reintentar el registro?")) {
                    break;
                }
            }
        }
    }

    private void consultarDetalleActivo() {
        ActivoRed activo = solicitarActivoExistente();
        if (activo == null) {
            return;
        }
        System.out.println("\nDetalle de " + activo);
        System.out.printf("Factor de Criticidad: %.2f | Exposición: %s | CVSS Consolidado: %.1f (%s)%n",
                activo.calcularFactorCriticidad(), activo.getNivelExposicion(),
                activo.getPuntajeCVSS(), motorCVSS.obtenerEtiquetaSeveridad(activo.getPuntajeCVSS()));
        System.out.println("Puertos abiertos (" + activo.getPuertos().size() + "):");
        if (activo.getPuertos().isEmpty()) {
            System.out.println("  (Sin puertos)");
        } else {
            for (PuertoServicio p : activo.getPuertos()) {
                System.out.println("  - " + p);
            }
        }
        System.out.println("Vulnerabilidades asociadas (" + activo.getVulnerabilidades().size() + "):");
        if (activo.getVulnerabilidades().isEmpty()) {
            System.out.println("  (Sin vulnerabilidades vinculadas)");
        } else {
            for (Vulnerabilidad v : activo.getVulnerabilidades()) {
                System.out.println("  - " + v);
            }
        }
    }

    private void actualizarActivoConsola() {
        ActivoRed activo = solicitarActivoExistente();
        if (activo == null) {
            return;
        }
        while (true) {
            try {
                String nuevaIP = leerIPv4("Nueva IPv4 (actual " + activo.getDireccionIP() + "): ");
                String nuevoHost = leerTextoNoVacio("Nuevo Hostname (actual " + activo.getHostname() + "): ");
                String nuevoSO = leerTextoNoVacio("Nuevo SO (actual " + activo.getSistemaOperativo() + "): ");
                inventario.actualizarActivo(activo.getIdActivo(), nuevaIP, nuevoHost, nuevoSO);
                System.out.println("Activo actualizado: " + activo);
                break;
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
                if (!leerSiNo("¿Reintentar actualización?")) {
                    break;
                }
            }
        }
    }

    private void eliminarActivoConsola() {
        ActivoRed activo = solicitarActivoExistente();
        if (activo == null) {
            return;
        }
        if (!leerSiNo("¿Confirma eliminar el activo " + activo.getIdActivo()
                + " y sus enlaces/acciones vinculadas?")) {
            return;
        }
        try {
            inventario.eliminarActivo(activo.getIdActivo());
            simulador.eliminarEnlacesDeActivo(activo.getIdActivo());
            optimizador.eliminarAccionesDeActivo(activo.getIdActivo());
            System.out.println("Activo eliminado junto con sus dependencias.");
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void agregarPuertoConsola() {
        ActivoRed activo = solicitarActivoExistente();
        if (activo == null) {
            return;
        }
        while (true) {
            try {
                PuertoServicio puerto = leerPuertoServicio();
                List<String> alertas = inventario.agregarPuertoAActivo(activo.getIdActivo(), puerto);
                System.out.println("Puerto agregado. Exposición actual del activo: " + activo.getNivelExposicion());
                alertas.forEach(System.out::println);
                break;
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
                if (!leerSiNo("¿Reintentar?")) {
                    break;
                }
            }
        }
    }

    private void removerPuertoConsola() {
        ActivoRed activo = solicitarActivoExistente();
        if (activo == null) {
            return;
        }
        int num = leerEnteroEnRango("Número de puerto a remover (1-65535): ", 1, 65535);
        String proto = leerProtocolo("Protocolo (TCP/UDP): ");
        try {
            boolean removido = inventario.removerPuertoDeActivo(activo.getIdActivo(), num, proto);
            if (removido) {
                System.out.println("Puerto removido. Nueva exposición: " + activo.getNivelExposicion());
            } else {
                System.out.println("El puerto " + num + "/" + proto + " no estaba registrado en el activo.");
            }
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void mostrarAlertasExposicion() {
        List<ActivoRed> activos = inventario.listarActivos();
        if (activos.isEmpty()) {
            System.out.println("No hay activos en el inventario.");
            return;
        }
        System.out.println("\n=== REPORTE DE EXPOSICIÓN PERIMETRAL ===");
        int totalAlertas = 0;
        for (ActivoRed a : activos) {
            try {
                List<String> alertas = inventario.generarAlertasExposicion(a);
                System.out.printf("Activo %-8s (%-15s): Exposición %-8s | Puertos abiertos: %d%n",
                        a.getIdActivo(), a.getHostname(), a.getNivelExposicion(), a.getPuertos().size());
                for (String al : alertas) {
                    System.out.println("   -> " + al);
                    totalAlertas++;
                }
            } catch (AuditoriaException ignored) {
            }
        }
        System.out.println("Total de alertas de servicios inseguros detectadas: " + totalAlertas);
    }

    private void menuModulo2() {
        boolean volver = false;
        while (!volver) {
            System.out.println("\n--- MÓDULO 2: VULNERABILIDADES Y CÁLCULO CVSS ---");
            System.out.println("1. Listar catálogo CVE");
            System.out.println("2. Registrar nueva vulnerabilidad CVE");
            System.out.println("3. Actualizar vulnerabilidad CVE");
            System.out.println("4. Eliminar vulnerabilidad del catálogo");
            System.out.println("5. Asociar CVE a un activo");
            System.out.println("6. Desasociar CVE de un activo");
            System.out.println("7. Ver matriz de severidad CVSS consolidada por activo");
            System.out.println("0. Volver al menú principal");
            int op = leerEnteroEnRango("Opción: ", 0, 7);

            switch (op) {
                case 1 -> listarCatalogoCVE();
                case 2 -> registrarVulnerabilidadConsola();
                case 3 -> actualizarVulnerabilidadConsola();
                case 4 -> eliminarVulnerabilidadConsola();
                case 5 -> asociarCVEConsola();
                case 6 -> desasociarCVEConsola();
                case 7 -> mostrarMatrizCVSSActivos();
                case 0 -> volver = true;
                default -> System.out.println("Opción inválida.");
            }
        }
    }

    private void listarCatalogoCVE() {
        List<Vulnerabilidad> lista = motorCVSS.listarCatalogo();
        if (lista.isEmpty()) {
            System.out.println("No hay vulnerabilidades registradas.");
            return;
        }
        System.out.println("\n---------------------------------------------------------------------------------------------------");
        System.out.printf("%-16s %-8s %-10s %-8s %-15s %-35s%n",
                "Código CVE", "CVSS", "Severidad", "Vector", "SO Afectado", "Descripción");
        System.out.println("---------------------------------------------------------------------------------------------------");
        for (Vulnerabilidad v : lista) {
            System.out.printf("%-16s %-8.1f %-10s %-8s %-15s %-35s%n",
                    v.getCodigoCVE(), v.calcularScoreCVSS(), v.obtenerEtiquetaSeveridad(),
                    v.getVectorAtaque(), recortar(v.getSoAfectado(), 15),
                    recortar(v.getDescripcion(), 35));
        }
        System.out.println("---------------------------------------------------------------------------------------------------");
    }

    private void registrarVulnerabilidadConsola() {
        while (true) {
            try {
                String codigo = leerCodigoCVE("Código CVE (ej. CVE-2023-1234): ");
                String desc = leerTextoNoVacio("Descripción: ");
                String so = leerTextoNoVacio("Sistema Operativo afectado: ");
                int puerto = leerEnteroEnRango("Puerto asociado (0 si no aplica, o 1-65535): ", 0, 65535);
                String vector = leerVectorAtaque("Vector de ataque (Remoto/Local): ");
                double[] cia = leerMetricasCIA();

                Vulnerabilidad v = new Vulnerabilidad(codigo, desc, so, puerto, vector, cia);
                motorCVSS.registrarVulnerabilidad(v);
                System.out.println("Vulnerabilidad registrada: " + v);
                break;
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
                if (!leerSiNo("¿Reintentar?")) {
                    break;
                }
            }
        }
    }

    private void actualizarVulnerabilidadConsola() {
        Vulnerabilidad v = solicitarCVEExistente();
        if (v == null) {
            return;
        }
        while (true) {
            try {
                String desc = leerTextoNoVacio("Nueva descripción: ");
                String so = leerTextoNoVacio("Nuevo SO afectado: ");
                int puerto = leerEnteroEnRango("Nuevo puerto asociado (0 o 1-65535): ", 0, 65535);
                String vector = leerVectorAtaque("Nuevo vector (Remoto/Local): ");
                double[] cia = leerMetricasCIA();
                motorCVSS.actualizarVulnerabilidad(v.getCodigoCVE(), desc, so, puerto, vector, cia);
                System.out.println("Vulnerabilidad actualizada: " + v);
                break;
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
                if (!leerSiNo("¿Reintentar?")) {
                    break;
                }
            }
        }
    }

    private void eliminarVulnerabilidadConsola() {
        Vulnerabilidad v = solicitarCVEExistente();
        if (v == null) {
            return;
        }
        try {
            motorCVSS.eliminarVulnerabilidad(v.getCodigoCVE());
            for (ActivoRed activo : inventario.listarActivos()) {
                activo.removerVulnerabilidad(v.getCodigoCVE());
            }
            System.out.println("Vulnerabilidad " + v.getCodigoCVE() + " eliminada.");
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void asociarCVEConsola() {
        ActivoRed activo = solicitarActivoExistente();
        if (activo == null) {
            return;
        }
        Vulnerabilidad v = solicitarCVEExistente();
        if (v == null) {
            return;
        }
        try {
            String nota = motorCVSS.asociarVulnerabilidadAActivo(v.getCodigoCVE(), activo);
            System.out.println("Asociación exitosa. " + nota);
            System.out.printf("Nuevo CVSS consolidado de %s: %.1f (%s)%n",
                    activo.getIdActivo(), activo.getPuntajeCVSS(),
                    motorCVSS.obtenerEtiquetaSeveridad(activo.getPuntajeCVSS()));
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void desasociarCVEConsola() {
        ActivoRed activo = solicitarActivoExistente();
        if (activo == null) {
            return;
        }
        String cve = leerCodigoCVE("Código CVE a desvincular: ");
        try {
            boolean ok = motorCVSS.desasociarVulnerabilidadDeActivo(cve, activo);
            System.out.println(ok ? "CVE desvinculado del activo." : "Ese activo no tenía vinculado el " + cve);
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void mostrarMatrizCVSSActivos() {
        List<ActivoRed> activos = inventario.listarActivos();
        if (activos.isEmpty()) {
            System.out.println("No hay activos registrados.");
            return;
        }
        System.out.println("\n---------------------------------------------------------------------------------------");
        System.out.printf("%-8s %-18s %-10s %-6s %-10s %-12s %-20s%n",
                "ID", "Hostname", "Exposición", "CVEs", "CVSS Cons.", "Severidad", "Criticidad Operativa");
        System.out.println("---------------------------------------------------------------------------------------");
        for (ActivoRed a : activos) {
            double score = a.getPuntajeCVSS();
            System.out.printf("%-8s %-18s %-10s %-6d %-10.1f %-12s %-20.2f%n",
                    a.getIdActivo(), recortar(a.getHostname(), 18), a.getNivelExposicion(),
                    a.getVulnerabilidades().size(), score,
                    motorCVSS.obtenerEtiquetaSeveridad(score), a.calcularFactorCriticidad());
        }
        System.out.println("---------------------------------------------------------------------------------------");
    }

    private void menuModulo3() {
        boolean volver = false;
        while (!volver) {
            System.out.println("\n--- MÓDULO 3: TOPOLOGÍA DE RED Y PROPAGACIÓN ---");
            System.out.println("1. Listar enlaces de red");
            System.out.println("2. Registrar nuevo enlace");
            System.out.println("3. Modificar medio o estado de enlace");
            System.out.println("4. Eliminar enlace");
            System.out.println("5. Ver matriz de adyacencia (probabilidad de salto)");
            System.out.println("6. Simular propagación desde 'Paciente Cero' (Efecto Dominó)");
            System.out.println("0. Volver al menú principal");
            int op = leerEnteroEnRango("Opción: ", 0, 6);

            switch (op) {
                case 1 -> listarEnlacesTabla();
                case 2 -> registrarEnlaceConsola();
                case 3 -> actualizarEnlaceConsola();
                case 4 -> eliminarEnlaceConsola();
                case 5 -> mostrarMatrizAdyacencia();
                case 6 -> ejecutarSimulacionPropagacion();
                case 0 -> volver = true;
                default -> System.out.println("Opción inválida.");
            }
        }
    }

    private void listarEnlacesTabla() {
        List<EnlaceRed> enlaces = simulador.listarEnlaces();
        if (enlaces.isEmpty()) {
            System.out.println("No hay enlaces registrados.");
            return;
        }
        System.out.println("\n--------------------------------------------------------------------------");
        System.out.printf("%-10s %-10s %-10s %-10s %-10s %-12s%n",
                "ID", "Origen", "Destino", "Medio", "Estado", "Prob. Salto");
        System.out.println("--------------------------------------------------------------------------");
        for (EnlaceRed e : enlaces) {
            System.out.printf("%-10s %-10s %-10s %-10s %-10s %-11.0f%%%n",
                    e.getIdEnlace(), e.getOrigen().getIdActivo(), e.getDestino().getIdActivo(),
                    e.getTipoMedio(), e.estaActivo() ? "Activo" : "Inactivo",
                    e.calcularProbSalto() * 100.0);
        }
        System.out.println("--------------------------------------------------------------------------");
    }

    private void registrarEnlaceConsola() {
        if (inventario.cantidadActivos() < 2) {
            System.out.println("Se requieren al menos 2 activos para crear un enlace.");
            return;
        }
        listarActivosTabla();
        while (true) {
            try {
                String id = leerTextoNoVacio("ID del enlace (ej. LNK-08): ");
                System.out.print("Origen -> ");
                ActivoRed origen = solicitarActivoExistente();
                if (origen == null) {
                    return;
                }
                System.out.print("Destino -> ");
                ActivoRed destino = solicitarActivoExistente();
                if (destino == null) {
                    return;
                }
                String medio = leerTipoMedio("Tipo de medio (LAN/WLAN/Troncal): ");
                boolean activo = leerSiNo("¿El enlace está activo?");
                EnlaceRed nuevo = new EnlaceRed(id, origen, destino, medio, activo);
                simulador.registrarEnlace(nuevo);
                System.out.println("Enlace registrado: " + nuevo);
                break;
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
                if (!leerSiNo("¿Reintentar?")) {
                    break;
                }
            }
        }
    }

    private void actualizarEnlaceConsola() {
        String id = leerTextoNoVacio("ID del enlace a modificar: ");
        try {
            EnlaceRed e = simulador.buscarEnlacePorId(id);
            String medio = leerTipoMedio("Nuevo medio (LAN/WLAN/Troncal): ");
            boolean activo = leerSiNo("¿Enlace activo?");
            simulador.actualizarEnlace(e.getIdEnlace(), medio, activo);
            System.out.println("Enlace actualizado: " + e);
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void eliminarEnlaceConsola() {
        String id = leerTextoNoVacio("ID del enlace a eliminar: ");
        try {
            EnlaceRed eliminado = simulador.eliminarEnlace(id);
            System.out.println("Enlace eliminado: " + eliminado.getIdEnlace());
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void mostrarMatrizAdyacencia() {
        List<ActivoRed> activos = inventario.listarActivos();
        if (activos.isEmpty()) {
            System.out.println("No hay activos en el inventario.");
            return;
        }
        double[][] matriz = simulador.construirMatrizAdyacencia(activos);
        System.out.println("\n=== MATRIZ DE ADYACENCIA (Probabilidad de Salto Lateral) ===");
        System.out.printf("%-10s", "Orig\\Dest");
        for (ActivoRed a : activos) {
            System.out.printf("%-9s", a.getIdActivo());
        }
        System.out.println();
        for (int i = 0; i < activos.size(); i++) {
            System.out.printf("%-10s", activos.get(i).getIdActivo());
            for (int j = 0; j < activos.size(); j++) {
                System.out.printf("%-9.2f", matriz[i][j]);
            }
            System.out.println();
        }
    }

    private void ejecutarSimulacionPropagacion() {
        listarActivosTabla();
        ActivoRed pacienteCero = solicitarActivoExistente();
        if (pacienteCero == null) {
            return;
        }
        String vector = leerTextoNoVacio("Vector de compromiso (ej. Ransomware / Remoto / Local): ");
        try {
            SimuladorPropagacion.ResultadoSimulacion res = simulador.simularPropagacion(
                    pacienteCero, vector, inventario.listarActivos());

            System.out.println("\n=== RESULTADO DEL RADIO DE EXPLOSIÓN Y EFECTO DOMINÓ ===");
            System.out.printf("Paciente Cero: %s (%s) | Vector: %s%n",
                    res.getPacienteCero().getIdActivo(), res.getPacienteCero().getHostname(),
                    res.getVectorCompromiso());
            System.out.printf("Nodos comprometidos: %d / %d (%.2f%% de la red) | Impacto Sistémico: %.2f%n",
                    res.getNodosComprometidos().size(), inventario.cantidadActivos(),
                    res.getPorcentajeRedAfectada(), res.getIndiceImpactoSistemico());

            System.out.println("\n---------------------------------------------------------------------------------------");
            System.out.printf("%-6s %-8s %-18s %-10s %-10s %-12s %-12s%n",
                    "Salto", "ID", "Hostname", "Desde", "Enlace", "Prob. Salto", "Prob. Acum.");
            System.out.println("---------------------------------------------------------------------------------------");
            for (SimuladorPropagacion.NodoComprometido n : res.getNodosComprometidos()) {
                System.out.printf("%-6d %-8s %-18s %-10s %-10s %-11.0f%% %-11.1f%%%n",
                        n.getSalto(), n.getActivo().getIdActivo(),
                        recortar(n.getActivo().getHostname(), 18),
                        n.getOrigenId(), n.getIdEnlace(),
                        n.getProbSalto() * 100.0, n.getProbAcumulada() * 100.0);
            }
            System.out.println("---------------------------------------------------------------------------------------");
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void menuModulo4() {
        boolean volver = false;
        while (!volver) {
            System.out.println("\n--- MÓDULO 4: PLAN DE MITIGACIÓN Y PRESUPUESTO ---");
            System.out.println("1. Listar acciones de mitigación");
            System.out.println("2. Registrar nueva acción de mitigación");
            System.out.println("3. Actualizar costos/riesgo de una acción");
            System.out.println("4. Eliminar acción de mitigación");
            System.out.println("5. Optimizar plan de parcheo según presupuesto ($)");
            System.out.println("6. Aplicar último plan optimizado o una acción individual");
            System.out.println("0. Volver al menú principal");
            int op = leerEnteroEnRango("Opción: ", 0, 6);

            switch (op) {
                case 1 -> listarMitigacionesTabla();
                case 2 -> registrarAccionConsola();
                case 3 -> actualizarAccionConsola();
                case 4 -> eliminarAccionConsola();
                case 5 -> ejecutarOptimizacionConsola();
                case 6 -> aplicarMitigacionesConsola();
                case 0 -> volver = true;
                default -> System.out.println("Opción inválida.");
            }
        }
    }

    private void listarMitigacionesTabla() {
        List<AccionMitigacion> lista = optimizador.listarAcciones();
        if (lista.isEmpty()) {
            System.out.println("No hay acciones de mitigación registradas.");
            return;
        }
        System.out.println("\n-------------------------------------------------------------------------------------------------------------");
        System.out.printf("%-8s %-8s %-15s %-25s %-10s %-7s %-10s %-10s %-10s%n",
                "ID", "Activo", "CVE", "Tipo Acción", "Costo ($)", "Horas", "Reducción", "Ratio B/C", "Estado");
        System.out.println("-------------------------------------------------------------------------------------------------------------");
        for (AccionMitigacion a : lista) {
            System.out.printf("%-8s %-8s %-15s %-25s %-10.2f %-7.1f %-10.1f %-10.4f %-10s%n",
                    a.getIdAccion(), a.getActivo().getIdActivo(), a.getVulnerabilidad().getCodigoCVE(),
                    recortar(a.getTipoAccion(), 25), a.getCostoEstimado(), a.getHorasHombre(),
                    a.getReduccionRiesgo(), a.calcularRatioCostoBeneficio(),
                    a.isAplicada() ? "Aplicada" : "Pendiente");
        }
        System.out.println("-------------------------------------------------------------------------------------------------------------");
    }

    private void registrarAccionConsola() {
        while (true) {
            try {
                String id = leerTextoNoVacio("ID de acción (ej. MIT-08): ");
                ActivoRed activo = solicitarActivoExistente();
                if (activo == null) {
                    return;
                }
                Vulnerabilidad cve = solicitarCVEExistente();
                if (cve == null) {
                    return;
                }
                String tipo = leerTextoNoVacio(
                        "Tipo de acción (Actualización de parche / Reconfiguración de puerto / Reemplazo de SO): ");
                double costo = leerDoublePositivo("Costo monetario estimado ($): ");
                double horas = leerDoublePositivo("Horas hombre requeridas: ");
                double reduccion = leerDoublePositivo("Puntos de reducción de riesgo: ");

                AccionMitigacion accion = new AccionMitigacion(id, activo, cve, tipo, costo, horas, reduccion);
                optimizador.registrarAccion(accion);
                System.out.println("Acción registrada: " + accion);
                break;
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
                if (!leerSiNo("¿Reintentar?")) {
                    break;
                }
            }
        }
    }

    private void actualizarAccionConsola() {
        String id = leerTextoNoVacio("ID de acción a actualizar: ");
        try {
            AccionMitigacion a = optimizador.buscarAccionPorId(id);
            String tipo = leerTextoNoVacio("Nuevo tipo de acción (actual " + a.getTipoAccion() + "): ");
            double costo = leerDoublePositivo("Nuevo costo ($): ");
            double horas = leerDoublePositivo("Nuevas horas hombre: ");
            double reduccion = leerDoublePositivo("Nueva reducción de riesgo: ");
            optimizador.actualizarAccion(a.getIdAccion(), tipo, costo, horas, reduccion);
            System.out.println("Acción actualizada: " + a);
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void eliminarAccionConsola() {
        String id = leerTextoNoVacio("ID de acción a eliminar: ");
        try {
            AccionMitigacion eliminada = optimizador.eliminarAccion(id);
            System.out.println("Acción eliminada: " + eliminada.getIdAccion());
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void ejecutarOptimizacionConsola() {
        double presupuesto = leerDoublePositivo("Presupuesto máximo disponible ($): ");
        try {
            OptimizadorMitigacion.PlanMitigacion plan = optimizador.optimizarPlanMitigacion(
                    presupuesto, simulador.getUltimaSimulacion());
            this.ultimoPlan = plan;

            System.out.println("\n=== PLAN ÓPTIMO DE MITIGACIÓN (MOCHILA 0/1) ===");
            if (simulador.getUltimaSimulacion() != null) {
                System.out.println("(Ponderado con impacto de propagación desde "
                        + simulador.getUltimaSimulacion().getPacienteCero().getIdActivo() + ")");
            }
            System.out.printf("Presupuesto: $%.2f | Costo del Plan: $%.2f | Remanente: $%.2f%n",
                    plan.getPresupuestoMaximo(), plan.getCostoTotal(), plan.getPresupuestoRestante());
            System.out.printf("Horas totales: %.1f h | Reducción base: %.2f pts | Reducción ponderada: %.2f pts%n",
                    plan.getHorasTotales(), plan.getReduccionRiesgoTotal(), plan.getReduccionPonderada());

            if (plan.getAccionesSeleccionadas().isEmpty()) {
                System.out.println("No existen acciones pendientes que quepan dentro del presupuesto ingresado.");
                return;
            }
            System.out.println("\nSecuencia priorizada de ejecución:");
            int orden = 1;
            for (AccionMitigacion a : plan.getAccionesSeleccionadas()) {
                System.out.printf("  %d. %s%n", orden++, a);
            }
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void aplicarMitigacionesConsola() {
        System.out.println("1) Aplicar último plan optimizado   2) Aplicar una acción específica por ID");
        int modo = leerEnteroEnRango("Seleccione: ", 1, 2);
        if (modo == 1) {
            if (ultimoPlan == null || ultimoPlan.getAccionesSeleccionadas().isEmpty()) {
                System.out.println("Primero genere un plan optimizado en la opción 5.");
                return;
            }
            int aplicadas = optimizador.aplicarPlan(ultimoPlan);
            System.out.println("Se aplicaron " + aplicadas + " medidas correctivas del plan optimizado.");
        } else {
            String id = leerTextoNoVacio("ID de la acción a aplicar: ");
            try {
                AccionMitigacion a = optimizador.buscarAccionPorId(id);
                if (a.isAplicada()) {
                    System.out.println("La acción " + a.getIdAccion() + " ya fue aplicada anteriormente.");
                } else {
                    a.aplicarParche();
                    System.out.println("Parche aplicado sobre " + a.getActivo().getIdActivo()
                            + ". Nuevo CVSS del activo: " + a.getActivo().getPuntajeCVSS());
                }
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private void menuModulo5() {
        boolean volver = false;
        while (!volver) {
            System.out.println("\n--- MÓDULO 5: REPORTES DE CUMPLIMIENTO Y AUDITORÍA ---");
            System.out.println("1. Listar perfiles de auditoría");
            System.out.println("2. Crear perfil de auditoría");
            System.out.println("3. Actualizar umbrales y validez de un perfil");
            System.out.println("4. Seleccionar perfil activo");
            System.out.println("5. Eliminar perfil de auditoría");
            System.out.println("6. Ejecutar auditoría técnica y emitir dictamen");
            System.out.println("0. Volver al menú principal");
            int op = leerEnteroEnRango("Opción: ", 0, 6);

            switch (op) {
                case 1 -> listarPerfilesAuditoria();
                case 2 -> crearPerfilAuditoria();
                case 3 -> actualizarPerfilAuditoria();
                case 4 -> seleccionarPerfilAuditoria();
                case 5 -> eliminarPerfilAuditoria();
                case 6 -> ejecutarAuditoriaConsola();
                case 0 -> volver = true;
                default -> System.out.println("Opción inválida.");
            }
        }
    }

    private void listarPerfilesAuditoria() {
        List<ReporteAuditoria> perfiles = auditoria.listarPerfiles();
        if (perfiles.isEmpty()) {
            System.out.println("No hay perfiles configurados.");
            return;
        }
        String activoId = "";
        try {
            activoId = auditoria.getPerfilActivo().getIdAuditoria();
        } catch (AuditoriaException ignored) {
        }
        System.out.println("\n------------------------------------------------------------------------------------------");
        System.out.printf("%-16s %-12s %-14s %-12s %-10s %-18s%n",
                "ID Auditoría", "Tolerancia", "Cobertura (%)", "Validez", "Score (%)", "Último Dictamen");
        System.out.println("------------------------------------------------------------------------------------------");
        for (ReporteAuditoria p : perfiles) {
            String marca = p.getIdAuditoria().equals(activoId) ? " *" : "";
            System.out.printf("%-16s %-12.1f %-14.1f %-12s %-10.2f %-18s%n",
                    p.getIdAuditoria() + marca, p.getUmbralTolerancia(),
                    p.getPorcentajeCoberturaExigido(), p.getFechaValidez(),
                    p.getScoreGlobal(), p.getDictamen());
        }
        System.out.println("------------------------------------------------------------------------------------------");
        System.out.println("(* indica el perfil activo por defecto)");
    }

    private void crearPerfilAuditoria() {
        while (true) {
            try {
                String id = leerTextoNoVacio("ID de auditoría (ej. AUD-ISO-2026): ");
                double umbral = leerDoubleEnRango("Tolerancia máxima CVSS permitida (0.0 - 10.0): ", 0.0, 10.0);
                double cobertura = leerDoubleEnRango("Porcentaje de cobertura exigido (0 - 100): ", 0.0, 100.0);
                LocalDate fecha = leerFecha("Fecha de validez (AAAA-MM-DD): ");
                ReporteAuditoria perfil = new ReporteAuditoria(id, umbral, cobertura, fecha);
                auditoria.registrarPerfil(perfil);
                System.out.println("Perfil creado: " + perfil.getIdAuditoria());
                break;
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
                if (!leerSiNo("¿Reintentar?")) {
                    break;
                }
            }
        }
    }

    private void actualizarPerfilAuditoria() {
        String id = leerTextoNoVacio("ID del perfil a actualizar: ");
        try {
            auditoria.buscarPerfilPorId(id);
            double umbral = leerDoubleEnRango("Nueva tolerancia máxima CVSS (0.0 - 10.0): ", 0.0, 10.0);
            double cobertura = leerDoubleEnRango("Nuevo porcentaje de cobertura exigido (0 - 100): ", 0.0, 100.0);
            LocalDate fecha = leerFecha("Nueva fecha de validez (AAAA-MM-DD): ");
            auditoria.actualizarPerfil(id, umbral, cobertura, fecha);
            System.out.println("Perfil actualizado correctamente.");
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void seleccionarPerfilAuditoria() {
        String id = leerTextoNoVacio("ID del perfil a activar: ");
        try {
            auditoria.seleccionarPerfilActivo(id);
            System.out.println("Perfil activo cambiado a: " + auditoria.getPerfilActivo().getIdAuditoria());
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void eliminarPerfilAuditoria() {
        String id = leerTextoNoVacio("ID del perfil a eliminar: ");
        try {
            ReporteAuditoria eliminado = auditoria.eliminarPerfil(id);
            System.out.println("Perfil eliminado: " + eliminado.getIdAuditoria());
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void ejecutarAuditoriaConsola() {
        System.out.print("ID de perfil (Enter para usar perfil activo): ");
        String id = scanner.nextLine().trim();
        try {
            ReporteAuditoria rep = auditoria.ejecutarAuditoria(id, inventario, optimizador, simulador);
            System.out.println("\n================ DICTAMEN DE AUDITORÍA TÉCNICA ================");
            System.out.printf("Perfil Evaluado : %s (Vigencia: %s)%n", rep.getIdAuditoria(), rep.getFechaValidez());
            System.out.printf("Umbral CVSS     : <= %.1f | Cobertura Exigida: %.1f%%%n",
                    rep.getUmbralTolerancia(), rep.getPorcentajeCoberturaExigido());
            System.out.printf("SCORE GLOBAL    : %.2f%%%n", rep.getScoreGlobal());
            System.out.printf("DICTAMEN FINAL  : %s%n", rep.getDictamen().toUpperCase());

            List<String> brechas = rep.listarBrechasPendientes();
            System.out.println("\nBrechas detectadas (" + brechas.size() + "):");
            if (brechas.isEmpty()) {
                System.out.println("  Ninguna. La infraestructura cumple con todos los criterios.");
            } else {
                for (int i = 0; i < brechas.size(); i++) {
                    System.out.printf("  %d. %s%n", i + 1, brechas.get(i));
                }
            }
            System.out.println("===============================================================");
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private void mostrarResumenEjecutivo() {
        System.out.println("\n================ RESUMEN EJECUTIVO DE INFRAESTRUCTURA ================");
        listarActivosTabla();
        mostrarAlertasExposicion();
        try {
            ReporteAuditoria rep = auditoria.ejecutarAuditoria(null, inventario, optimizador, simulador);
            System.out.printf("%nScore Global Actual: %.2f%% | Dictamen: %s | Brechas: %d%n",
                    rep.getScoreGlobal(), rep.getDictamen(), rep.listarBrechasPendientes().size());
        } catch (AuditoriaException ex) {
            System.out.println("Auditoría no ejecutada: " + ex.getMessage());
        }
        System.out.println("======================================================================");
    }

    private void recargarDemo() {
        if (!leerSiNo("¿Desea reiniciar y cargar nuevamente los datos iniciales PYME?")) {
            return;
        }
        try {
            for (ActivoRed a : inventario.listarActivos()) {
                inventario.eliminarActivo(a.getIdActivo());
            }
            for (Vulnerabilidad v : motorCVSS.listarCatalogo()) {
                motorCVSS.eliminarVulnerabilidad(v.getCodigoCVE());
            }
            for (EnlaceRed e : simulador.listarEnlaces()) {
                simulador.eliminarEnlace(e.getIdEnlace());
            }
            for (AccionMitigacion ac : optimizador.listarAcciones()) {
                optimizador.eliminarAccion(ac.getIdAccion());
            }
            for (ReporteAuditoria p : auditoria.listarPerfiles()) {
                auditoria.eliminarPerfil(p.getIdAuditoria());
            }

            DatosIniciales.cargarTopologiaPYME(inventario, motorCVSS, simulador, optimizador, auditoria);
            simulador.reiniciarSimulacion();
            this.ultimoPlan = null;
            System.out.println("Topología PYME de demostración recargada correctamente.");
        } catch (AuditoriaException ex) {
            System.out.println("[ERROR] " + ex.getMessage());
        }
    }

    private ActivoRed solicitarActivoExistente() {
        if (inventario.cantidadActivos() == 0) {
            System.out.println("El inventario está vacío.");
            return null;
        }
        while (true) {
            String id = leerTextoNoVacio("ID del activo (o 'SALIR' para cancelar): ");
            if ("SALIR".equalsIgnoreCase(id)) {
                return null;
            }
            try {
                return inventario.buscarActivoPorId(id);
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private Vulnerabilidad solicitarCVEExistente() {
        if (motorCVSS.listarCatalogo().isEmpty()) {
            System.out.println("El catálogo CVE está vacío.");
            return null;
        }
        while (true) {
            String cve = leerTextoNoVacio("Código CVE (o 'SALIR' para cancelar): ");
            if ("SALIR".equalsIgnoreCase(cve)) {
                return null;
            }
            try {
                return motorCVSS.buscarPorCVE(cve);
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private PuertoServicio leerPuertoServicio() {
        while (true) {
            try {
                int num = leerEnteroEnRango("Número de puerto (1-65535): ", 1, 65535);
                String proto = leerProtocolo("Protocolo (TCP/UDP): ");
                String serv = leerTextoNoVacio("Nombre del servicio (ej. SSH, Telnet, FTP, SMB, HTTPS): ");
                return new PuertoServicio(num, proto, serv);
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private double[] leerMetricasCIA() {
        System.out.println("Ingrese métricas de impacto CIA en [0.00, 1.00] (CVSS estándar: Ninguno=0.0, Bajo=0.22, Alto=0.56):");
        double c = leerDoubleEnRango("  Confidencialidad (C): ", 0.0, 1.0);
        double i = leerDoubleEnRango("  Integridad (I): ", 0.0, 1.0);
        double a = leerDoubleEnRango("  Disponibilidad (A): ", 0.0, 1.0);
        return new double[]{c, i, a};
    }

    private String leerTextoNoVacio(String prompt) {
        while (true) {
            System.out.print(prompt);
            String entrada = scanner.nextLine();
            try {
                return ValidadorDatos.validarTextoNoVacio(entrada, "Entrada");
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] Debe ingresar un texto válido.");
            }
        }
    }

    private String leerIPv4(String prompt) {
        while (true) {
            System.out.print(prompt);
            try {
                return ValidadorDatos.validarIPv4(scanner.nextLine());
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private String leerCodigoCVE(String prompt) {
        while (true) {
            System.out.print(prompt);
            try {
                return ValidadorDatos.validarCodigoCVE(scanner.nextLine());
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private String leerProtocolo(String prompt) {
        while (true) {
            System.out.print(prompt);
            try {
                return ValidadorDatos.validarProtocolo(scanner.nextLine());
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private String leerTipoMedio(String prompt) {
        while (true) {
            System.out.print(prompt);
            try {
                return ValidadorDatos.validarTipoMedio(scanner.nextLine());
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private String leerVectorAtaque(String prompt) {
        while (true) {
            System.out.print(prompt);
            try {
                return ValidadorDatos.validarVectorAtaque(scanner.nextLine());
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private String leerTipoEquipo(String prompt) {
        while (true) {
            System.out.print(prompt);
            try {
                return ValidadorDatos.validarTipoEquipoRed(scanner.nextLine());
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private LocalDate leerFecha(String prompt) {
        while (true) {
            System.out.print(prompt);
            try {
                return ValidadorDatos.validarFechaISO(scanner.nextLine());
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private int leerEnteroEnRango(String prompt, int min, int max) {
        while (true) {
            System.out.print(prompt);
            String linea = scanner.nextLine().trim();
            try {
                int valor = Integer.parseInt(linea);
                if (valor < min || valor > max) {
                    System.out.printf("[ERROR] El número debe estar entre %d y %d.%n", min, max);
                    continue;
                }
                return valor;
            } catch (NumberFormatException ex) {
                System.out.println("[ERROR] Ingrese un número entero válido.");
            }
        }
    }

    private double leerDoublePositivo(String prompt) {
        while (true) {
            System.out.print(prompt);
            String linea = scanner.nextLine().trim().replace(',', '.');
            try {
                double val = Double.parseDouble(linea);
                return ValidadorDatos.validarPositivo(val, "Valor");
            } catch (NumberFormatException ex) {
                System.out.println("[ERROR] Ingrese un valor numérico válido.");
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private double leerDoubleEnRango(String prompt, double min, double max) {
        while (true) {
            System.out.print(prompt);
            String linea = scanner.nextLine().trim().replace(',', '.');
            try {
                double val = Double.parseDouble(linea);
                return ValidadorDatos.validarRango(val, min, max, "Valor");
            } catch (NumberFormatException ex) {
                System.out.println("[ERROR] Ingrese un número decimal válido.");
            } catch (AuditoriaException ex) {
                System.out.println("[ERROR] " + ex.getMessage());
            }
        }
    }

    private boolean leerSiNo(String prompt) {
        while (true) {
            System.out.print(prompt + " (S/N): ");
            String resp = scanner.nextLine().trim().toUpperCase();
            if ("S".equals(resp) || "SI".equals(resp) || "SÍ".equals(resp)) {
                return true;
            }
            if ("N".equals(resp) || "NO".equals(resp)) {
                return false;
            }
            System.out.println("[ERROR] Responda con S o N.");
        }
    }

    private String recortar(String texto, int max) {
        if (texto == null) {
            return "";
        }
        return texto.length() <= max ? texto : texto.substring(0, max - 3) + "...";
    }
}
