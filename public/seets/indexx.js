fetch('/api/user-count')
.then(response => response.json())
.then(data => {
    // Menampilkan jumlah pengguna terdaftar
    document.getElementById('user-count').textContent = data.count;
})
.catch(error => {
    console.error('Error fetching user count:', error);
    document.getElementById('user-count').textContent = 'Error';
});

particlesJS("particles-js", {
particles: {
    number: {
        value: 100,
        density: {
            enable: true,
            value_area: 800
        }
    },
    color: {
        value: "#ff6f61"
    },
    shape: {
        type: "circle",
        stroke: {
            width: 0,
            color: "#000000"
        }
    },
    opacity: {
        value: 0.5,
        random: true,
        anim: {
            enable: true,
            speed: 1,
            opacity_min: 0.1,
            sync: false
        }
    },
    size: {
        value: 5,
        random: true
    },
    line_linked: {
        enable: true,
        distance: 150,
        color: "#ffffff",
        opacity: 0.9,
        width: 1
    },
    move: {
        enable: true,
        speed: 2,
        direction: "none",
        random: false,
        straight: false,
        out_mode: "out",
        bounce: false
    }
},
interactivity: {
    detect_on: "canvas",
    events: {
        onhover: {
            enable: true,
            mode: "grab"
        },
        onclick: {
            enable: true,
            mode: "push"
        },
        resize: true
    },
    modes: {
        grab: {
            distance: 140,
            line_linked: {
                opacity: 1
            }
        },
        push: {
            particles_nb: 4
        }
    }
},
retina_detect: true
});