const chart = document.getElementById("threatChart");

if (chart) {

    new Chart(chart, {

        type: "line",

        data: {

            labels: [
                "Mon",
                "Tue",
                "Wed",
                "Thu",
                "Fri",
                "Sat",
                "Sun"
            ],

            datasets: [
                {
                    label: "Threats",

                    data: [3, 5, 2, 8, 6, 9, 4],

                    borderColor: "#0d6efd",

                    backgroundColor: "rgba(13,110,253,0.2)",

                    fill: true,

                    tension: 0.4
                }
            ]

        },

        options: {

            responsive: true,

            plugins: {

                legend: {

                    labels: {

                        color: "white"

                    }

                }

            },

            scales: {

                x: {

                    ticks: {

                        color: "white"

                    }

                },

                y: {

                    ticks: {

                        color: "white"

                    }

                }

            }

        }

    });

}