-- ---------------------------------------------------------------------
-- Beispieldatei für ACI - Verstöße gegen die Trivadis Coding Guidelines.
-- Diese Datei dient ausschließlich Demonstrations- und Testzwecken und
-- löst zahlreiche Regeln der Gruppe "Coding Guidelines" aus.
-- ---------------------------------------------------------------------

CREATE PROCEDURE process_orders(customer_id NUMBER, p_mode IN VARCHAR2)
AS
    v_name    VARCHAR(100);     -- G-2320 VARCHAR, G-NC fehlendes l_
    l_code    CHAR(5);          -- G-2310 CHAR
    l_notes   LONG;             -- G-2510 LONG
    l_count   NUMBER;           -- G-2210 NUMBER ohne Genauigkeit
    n         PLS_INTEGER;      -- G-2185 zu kurzer Bezeichner
BEGIN
    /* Äußerer Kommentar /* verschachtelt */ Ende */   -- G-1070

    SELECT * INTO v_name FROM customers WHERE id = customer_id;  -- G-3145

    IF p_mode = 'A' THEN
        NULL;
    ELSIF p_mode = 'B' THEN
        NULL;
    ELSIF p_mode = 'C' THEN     -- G-4210 mehrere ELSIF-Zweige
        NULL;
    END IF;

    FOR i IN 1 .. 10 LOOP
        UPDATE orders SET status = 'X' WHERE id = i;
        COMMIT;                 -- G-3310 COMMIT innerhalb der Schleife
    END LOOP;

    IF l_count = l_count THEN   -- G-1080 gleicher Ausdruck beidseitig
        l_count := 0;
    END IF;

    l_count := DECODE(p_mode, 'A', 1, 0);     -- G-4220 DECODE
    l_notes := TO_DATE('2026-01-01');         -- G-9010 TO_DATE ohne Maske
EXCEPTION
    WHEN OTHERS THEN            -- G-5040 WHEN OTHERS
        DBMS_OUTPUT.PUT_LINE(SQLERRM);   -- G-5080 SQLERRM ohne BACKTRACE
END;
/
