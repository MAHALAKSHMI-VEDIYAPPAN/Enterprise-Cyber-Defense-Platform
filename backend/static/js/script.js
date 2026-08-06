const ctx = document.getElementById("threatChart");

if (ctx) {

    new Chart(ctx, {

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

                    label: "Detected Threats",

                    data: [2, 5, 3, 8, 6, 9, 4],

                    borderColor: "#3b82f6",

                    backgroundColor: "rgba(59,130,246,0.2)",

                    tension: 0.4,

                    fill: true

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