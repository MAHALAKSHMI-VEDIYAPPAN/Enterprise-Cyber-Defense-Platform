/* ==========================================================
   ECDP // ENTERPRISE CYBER DEFENSE PLATFORM
   Professional SOC Dashboard JavaScript
   ========================================================== */

document.addEventListener("DOMContentLoaded", function () {


    /* ======================================================
       THREAT ACTIVITY CHART
       ====================================================== */

    const chart =
        document.getElementById("threatChart");


    if (chart && typeof Chart !== "undefined") {

        new Chart(chart, {

            type: "line",

            data: {

                labels: [
                    "MON",
                    "TUE",
                    "WED",
                    "THU",
                    "FRI",
                    "SAT",
                    "SUN"
                ],

                datasets: [
                    {
                        label: "THREAT ACTIVITY",

                        data: [
                            3,
                            5,
                            2,
                            8,
                            6,
                            9,
                            4
                        ],

                        /* Professional blue/cyan */

                        borderColor: "#3B82F6",

                        backgroundColor:
                            "rgba(59, 130, 246, 0.08)",

                        pointBackgroundColor:
                            "#06B6D4",

                        pointBorderColor:
                            "#60A5FA",

                        pointHoverBackgroundColor:
                            "#FFFFFF",

                        pointHoverBorderColor:
                            "#22D3EE",

                        pointRadius: 3,

                        pointHoverRadius: 6,

                        borderWidth: 2,

                        fill: true,

                        tension: 0.35
                    }
                ]

            },


            options: {

                responsive: true,

                maintainAspectRatio: false,


                interaction: {

                    intersect: false,

                    mode: "index"

                },


                animation: {

                    duration: 1200,

                    easing: "easeOutQuart"

                },


                plugins: {

                    legend: {

                        display: true,

                        labels: {

                            color: "#CBD5E1",

                            font: {
                                size: 11,
                                weight: "600"
                            },

                            padding: 15

                        }

                    },


                    tooltip: {

                        backgroundColor:
                            "rgba(7, 11, 20, 0.95)",

                        titleColor:
                            "#60A5FA",

                        bodyColor:
                            "#E2E8F0",

                        borderColor:
                            "rgba(59, 130, 246, 0.35)",

                        borderWidth: 1,

                        padding: 10,

                        displayColors: false

                    }

                },


                scales: {

                    x: {

                        grid: {

                            color:
                                "rgba(148, 163, 184, 0.06)",

                            drawBorder: false

                        },

                        ticks: {

                            color:
                                "#64748B",

                            font: {

                                size: 10,

                                weight: "500"

                            }

                        }

                    },


                    y: {

                        beginAtZero: true,

                        grid: {

                            color:
                                "rgba(148, 163, 184, 0.06)",

                            drawBorder: false

                        },

                        ticks: {

                            color:
                                "#64748B",

                            font: {

                                size: 10,

                                weight: "500"

                            }

                        }

                    }

                }

            }

        });

    }


    /* ======================================================
       ECDP SYSTEM CLOCK
       ====================================================== */

    const clock =
        document.getElementById(
            "systemClock"
        );


    if (clock) {

        function updateClock() {

            const now = new Date();


            clock.textContent =
                now.toLocaleTimeString(
                    [],
                    {
                        hour12: false
                    }
                );

        }


        updateClock();


        setInterval(
            updateClock,
            1000
        );

    }


    /* ======================================================
       SYSTEM ONLINE INDICATOR
       ====================================================== */

    const systemStatus =
        document.querySelector(
            ".system-status"
        );


    if (systemStatus) {

        systemStatus.classList.add(
            "status-online"
        );

    }


    /* ======================================================
       ACTIVITY INDICATORS
       ====================================================== */

    const activityIndicators =
        document.querySelectorAll(
            ".activity-indicator"
        );


    activityIndicators.forEach(
        function (indicator) {

            indicator.classList.add(
                "status-online"
            );

        }
    );


    /* ======================================================
       KPI CARD ANIMATION
       ====================================================== */

    const kpiCards =
        document.querySelectorAll(
            ".soc-kpi-card"
        );


    kpiCards.forEach(
        function (card, index) {

            card.style.opacity = "0";

            card.style.transform =
                "translateY(12px)";


            setTimeout(
                function () {

                    card.style.transition =
                        "opacity 0.5s ease, transform 0.5s ease";

                    card.style.opacity = "1";

                    card.style.transform =
                        "translateY(0)";

                },
                100 + (index * 80)
            );

        }
    );


    /* ======================================================
       SOC PANEL ANIMATION
       ====================================================== */

    const panels =
        document.querySelectorAll(
            ".soc-panel"
        );


    panels.forEach(
        function (panel, index) {

            panel.style.opacity = "0";

            panel.style.transform =
                "translateY(10px)";


            setTimeout(
                function () {

                    panel.style.transition =
                        "opacity 0.55s ease, transform 0.55s ease";

                    panel.style.opacity = "1";

                    panel.style.transform =
                        "translateY(0)";

                },
                250 + (index * 100)
            );

        }
    );


    /* ======================================================
       SECURITY SCORE ANIMATION
       ====================================================== */

    const scoreElements =
        document.querySelectorAll(
            ".score-value"
        );


    scoreElements.forEach(
        function (element) {

            const finalValue =
                parseInt(
                    element.textContent
                );


            if (!isNaN(finalValue)) {

                let currentValue = 0;


                const duration = 900;

                const steps = 30;

                const increment =
                    finalValue / steps;


                const interval =
                    duration / steps;


                element.textContent =
                    "0%";


                const counter =
                    setInterval(
                        function () {

                            currentValue +=
                                increment;


                            if (
                                currentValue >=
                                finalValue
                            ) {

                                currentValue =
                                    finalValue;

                                clearInterval(
                                    counter
                                );

                            }


                            element.textContent =
                                Math.round(
                                    currentValue
                                ) + "%";

                        },
                        interval
                    );

            }

        }
    );


    /* ======================================================
       SCORE PROGRESS ANIMATION
       ====================================================== */

    const scoreBars =
        document.querySelectorAll(
            ".score-progress-fill"
        );


    scoreBars.forEach(
        function (bar) {

            const targetWidth =
                bar.style.width;


            bar.style.width = "0%";


            setTimeout(
                function () {

                    bar.style.transition =
                        "width 1.2s cubic-bezier(0.22, 1, 0.36, 1)";

                    bar.style.width =
                        targetWidth;

                },
                300
            );

        }
    );


    /* ======================================================
       RISK BAR ANIMATION
       ====================================================== */

    const riskBars =
        document.querySelectorAll(
            ".risk-fill"
        );


    riskBars.forEach(
        function (bar) {

            const targetWidth =
                bar.style.width;


            bar.style.width = "0%";


            setTimeout(
                function () {

                    bar.style.transition =
                        "width 1s ease";

                    bar.style.width =
                        targetWidth;

                },
                500
            );

        }
    );


    /* ======================================================
       TABLE ROW HOVER EFFECT
       ====================================================== */

    const tableRows =
        document.querySelectorAll(
            ".soc-table tbody tr"
        );


    tableRows.forEach(
        function (row) {

            row.addEventListener(
                "mouseenter",
                function () {

                    row.style.transform =
                        "translateX(2px)";

                }
            );


            row.addEventListener(
                "mouseleave",
                function () {

                    row.style.transform =
                        "translateX(0)";

                }
            );

        }
    );


    /* ======================================================
       SYSTEM STATUS PULSE
       ====================================================== */

    const statusIndicators =
        document.querySelectorAll(
            ".status-indicator"
        );


    statusIndicators.forEach(
        function (indicator) {

            indicator.classList.add(
                "status-online"
            );

        }
    );


    /* ======================================================
       CURRENT YEAR
       ====================================================== */

    const year =
        document.getElementById(
            "currentYear"
        );


    if (year) {

        year.textContent =
            new Date().getFullYear();

    }


});