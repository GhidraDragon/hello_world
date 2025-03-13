import cupy as cp
import numpy as np
import matplotlib.pyplot as plt

# Grid parameters
N = 128         # Grid size (N x N cells)
dt = 0.1        # Time step
diff = 0.0001   # Diffusion rate
visc = 0.0001   # Viscosity
iter = 20       # Number of iterations for the linear solver

# Helper: convert 2D indices to a single index (if needed)
def IX(i, j):
    return i + (N + 2) * j

# Allocate fields on the GPU (include 1-cell boundary padding)
shape = (N + 2, N + 2)
u     = cp.zeros(shape, dtype=cp.float32)  # velocity x-component
v     = cp.zeros(shape, dtype=cp.float32)  # velocity y-component
u_prev = cp.zeros(shape, dtype=cp.float32)
v_prev = cp.zeros(shape, dtype=cp.float32)
dens  = cp.zeros(shape, dtype=cp.float32)
dens_prev = cp.zeros(shape, dtype=cp.float32)

def add_source(x, s):
    x += dt * s

def set_bnd(b, x):
    # Simple boundary conditions: reflect velocity at boundaries, zero-gradient for scalars.
    # b = 1 for horizontal velocity; b = 2 for vertical velocity.
    # For indices 0 and N+1, mirror the values.
    x[0, 1:-1]   = cp.where(b == 1, -x[1, 1:-1], x[1, 1:-1])
    x[-1, 1:-1]  = cp.where(b == 1, -x[-2, 1:-1], x[-2, 1:-1])
    x[1:-1, 0]   = cp.where(b == 2, -x[1:-1, 1], x[1:-1, 1])
    x[1:-1, -1]  = cp.where(b == 2, -x[1:-1, -2], x[1:-1, -2])
    # Corners:
    x[0, 0]      = 0.5 * (x[1,0] + x[0,1])
    x[0, -1]     = 0.5 * (x[1,-1] + x[0,-2])
    x[-1, 0]     = 0.5 * (x[-2,0] + x[-1,1])
    x[-1, -1]    = 0.5 * (x[-2,-1] + x[-1,-2])

def lin_solve(b, x, x0, a, c):
    for k in range(iter):
        x[1:-1, 1:-1] = (x0[1:-1, 1:-1] + a * (x[0:-2, 1:-1] +
                                                   x[2:  , 1:-1] +
                                                   x[1:-1, 0:-2] +
                                                   x[1:-1, 2:  ])) / c
        set_bnd(b, x)

def diffuse(b, x, x0, diff_coef):
    a = dt * diff_coef * N * N
    lin_solve(b, x, x0, a, 1 + 4 * a)

def advect(b, d, d0, u, v):
    dt0 = dt * N
    # Create a grid of indices
    j, i = cp.meshgrid(cp.arange(1, N+1), cp.arange(1, N+1), indexing='ij')
    # Trace backwards in time
    x = i - dt0 * u[1:-1, 1:-1]
    y = j - dt0 * v[1:-1, 1:-1]
    # Clamp to valid coordinates
    x = cp.clip(x, 0.5, N + 0.5)
    y = cp.clip(y, 0.5, N + 0.5)
    
    i0 = cp.floor(x).astype(cp.int32)
    i1 = i0 + 1
    j0 = cp.floor(y).astype(cp.int32)
    j1 = j0 + 1

    s1 = x - i0
    s0 = 1 - s1
    t1 = y - j0
    t0 = 1 - t1

    # Bilinear interpolation
    d_interp = (s0 * (t0 * d0[j0, i0] + t1 * d0[j1, i0]) +
                s1 * (t0 * d0[j0, i1] + t1 * d0[j1, i1]))
    d[1:-1, 1:-1] = d_interp
    set_bnd(b, d)

def project(u, v, p, div):
    # Compute divergence and initialize pressure field
    div[1:-1, 1:-1] = -0.5 * (u[2:, 1:-1] - u[0:-2, 1:-1] +
                              v[1:-1, 2:] - v[1:-1, 0:-2]) / N
    p.fill(0)
    set_bnd(0, div)
    set_bnd(0, p)
    
    lin_solve(0, p, div, 1, 4)
    
    # Subtract gradient of pressure from velocity field
    u[1:-1, 1:-1] -= 0.5 * N * (p[2:, 1:-1] - p[0:-2, 1:-1])
    v[1:-1, 1:-1] -= 0.5 * N * (p[1:-1, 2:] - p[1:-1, 0:-2])
    set_bnd(1, u)
    set_bnd(2, v)

def velocity_step(u, v, u0, v0):
    add_source(u, u0)
    add_source(v, v0)
    u0[:] = u.copy()
    v0[:] = v.copy()
    diffuse(1, u, u0, visc)
    diffuse(2, v, v0, visc)
    project(u, v, u0, v0)
    u0[:] = u.copy()
    v0[:] = v.copy()
    advect(1, u, u0, u0, v0)
    advect(2, v, v0, u0, v0)
    project(u, v, u0, v0)

def density_step(x, x0, u, v):
    add_source(x, x0)
    x0[:] = x.copy()
    diffuse(0, x, x0, diff)
    x0[:] = x.copy()
    advect(0, x, x0, u, v)

# Example: initialize a density blob and a velocity source
def add_initial_conditions():
    # Place a density blob in the center
    cx, cy = N // 2, N // 2
    r = 10
    Y, X = cp.ogrid[:N+2, :N+2]
    mask = (X - cx)**2 + (Y - cy)**2 <= r**2
    dens_prev[mask] = 100.0

    # Add a horizontal velocity to push the fluid to the right
    u_prev[cy-5:cy+5, cx-5:cx+5] = 5.0

# Main simulation loop
def run_simulation(steps=200, display_interval=20):
    global u, v, u_prev, v_prev, dens, dens_prev
    add_initial_conditions()
    
    # For pressure solve in project()
    p   = cp.zeros(shape, dtype=cp.float32)
    div = cp.zeros(shape, dtype=cp.float32)
    
    for step in range(steps):
        # Clear previous source arrays
        u_prev.fill(0)
        v_prev.fill(0)
        dens_prev.fill(0)
        
        # Here you could update u_prev, v_prev, dens_prev based on user input or external forces
        
        # Step velocity and density fields
        velocity_step(u, v, u_prev, v_prev)
        density_step(dens, dens_prev, u, v)
        
        if step % display_interval == 0:
            # Bring the density field back to CPU for visualization
            dens_cpu = cp.asnumpy(dens)
            plt.clf()
            plt.imshow(dens_cpu[1:-1, 1:-1], cmap='inferno', origin='lower')
            plt.title(f"Density at step {step}")
            plt.pause(0.001)
    plt.show()

if __name__ == "__main__":
    # Ensure interactive plotting mode is on
    plt.ion()
    run_simulation()
