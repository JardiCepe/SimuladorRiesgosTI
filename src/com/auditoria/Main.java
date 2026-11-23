package com.auditoria;

import com.auditoria.interfaz.MenuConsola;
import com.auditoria.negocio.AuditoriaService;
import com.auditoria.negocio.GestorInventario;
import com.auditoria.negocio.MotorCVSS;
import com.auditoria.negocio.OptimizadorMitigacion;
import com.auditoria.negocio.SimuladorPropagacion;
import com.auditoria.util.AuditoriaException;
import com.auditoria.util.DatosIniciales;

public class Main {

    public static void main(String[] args) {
        GestorInventario inventario = new GestorInventario();
        MotorCVSS motorCVSS = new MotorCVSS();
        SimuladorPropagacion simulador = new SimuladorPropagacion();
        OptimizadorMitigacion optimizador = new OptimizadorMitigacion();
        AuditoriaService auditoria = new AuditoriaService();

        try {
            DatosIniciales.cargarTopologiaPYME(inventario, motorCVSS, simulador, optimizador, auditoria);
        } catch (AuditoriaException ex) {
            System.err.println("Advertencia al cargar datos iniciales: " + ex.getMessage());
        }

        MenuConsola menu = new MenuConsola(inventario, motorCVSS, simulador, optimizador, auditoria);
        menu.iniciar();
    }
}
