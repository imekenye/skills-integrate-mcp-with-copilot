// Application State
let currentUser = null;
let authToken = null;

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const activitiesList = document.getElementById("activities-list");
  const activitySelect = document.getElementById("activity");
  const adminActivitySelect = document.getElementById("admin-activity");
  const signupForm = document.getElementById("signup-form");
  const adminSignupForm = document.getElementById("admin-signup-form");
  const messageDiv = document.getElementById("message");
  
  // Auth Elements
  const loginToggleBtn = document.getElementById("login-toggle-btn");
  const userInfo = document.getElementById("user-info");
  const userDisplay = document.getElementById("user-display");
  const logoutBtn = document.getElementById("logout-btn");
  
  // Modal Elements
  const loginModal = document.getElementById("login-modal");
  const registerModal = document.getElementById("register-modal");
  const closeLoginModal = document.getElementById("close-login-modal");
  const closeRegisterModal = document.getElementById("close-register-modal");
  const showRegisterModal = document.getElementById("show-register-modal");
  const loginForm = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");
  const loginMessage = document.getElementById("login-message");
  const registerMessage = document.getElementById("register-message");
  
  // Container Elements
  const studentSignupContainer = document.getElementById("student-signup-container");
  const adminControlsContainer = document.getElementById("admin-controls-container");

  // Authentication Functions
  function getAuthHeaders() {
    return authToken ? { 'Authorization': `Bearer ${authToken}` } : {};
  }

  function showMessage(message, type = 'info', targetElement = messageDiv) {
    targetElement.textContent = message;
    targetElement.className = type;
    targetElement.classList.remove('hidden');
    
    setTimeout(() => {
      targetElement.classList.add('hidden');
    }, 5000);
  }

  function updateUIBasedOnAuth() {
    if (currentUser) {
      // Show user info, hide login button
      userDisplay.textContent = `Welcome, ${currentUser.full_name} (${currentUser.role})`;
      userInfo.classList.remove('hidden');
      loginToggleBtn.classList.add('hidden');
      
      // Show appropriate controls based on role
      if (currentUser.role === 'student') {
        studentSignupContainer.classList.remove('hidden');
        adminControlsContainer.classList.add('hidden');
      } else if (currentUser.role === 'club_admin' || currentUser.role === 'federation_admin') {
        studentSignupContainer.classList.add('hidden');
        adminControlsContainer.classList.remove('hidden');
      }
    } else {
      // Hide user info, show login button
      userInfo.classList.add('hidden');
      loginToggleBtn.classList.remove('hidden');
      studentSignupContainer.classList.add('hidden');
      adminControlsContainer.classList.add('hidden');
    }
  }

  async function checkAuthStatus() {
    const token = localStorage.getItem('authToken');
    if (!token) return;

    try {
      const response = await fetch('/auth/me', {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        authToken = token;
        currentUser = await response.json();
        updateUIBasedOnAuth();
      } else {
        localStorage.removeItem('authToken');
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      localStorage.removeItem('authToken');
    }
  }

  async function login(username, password) {
    try {
      const response = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const result = await response.json();

      if (response.ok) {
        authToken = result.access_token;
        localStorage.setItem('authToken', authToken);
        
        // Get user info
        const userResponse = await fetch('/auth/me', {
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (userResponse.ok) {
          currentUser = await userResponse.json();
          updateUIBasedOnAuth();
          closeModal(loginModal);
          showMessage(`Welcome back, ${currentUser.full_name}!`, 'success');
          fetchActivities();
        }
      } else {
        showMessage(result.detail || 'Login failed', 'error', loginMessage);
      }
    } catch (error) {
      showMessage('Login failed. Please try again.', 'error', loginMessage);
    }
  }

  function logout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('authToken');
    updateUIBasedOnAuth();
    showMessage('Logged out successfully', 'info');
    fetchActivities();
  }

  // Modal Functions
  function openModal(modal) {
    modal.classList.remove('hidden');
  }

  function closeModal(modal) {
    modal.classList.add('hidden');
    // Clear form data and messages
    if (modal === loginModal) {
      loginForm.reset();
      loginMessage.classList.add('hidden');
    } else if (modal === registerModal) {
      registerForm.reset();
      registerMessage.classList.add('hidden');
    }
  }

  // API Functions
  async function fetchActivities() {
    try {
      const response = await fetch("/activities", {
        headers: getAuthHeaders()
      });
      const activities = await response.json();

      // Clear loading message
      activitiesList.innerHTML = "";
      
      // Clear select options
      activitySelect.innerHTML = '<option value="">-- Select an activity --</option>';
      if (adminActivitySelect) {
        adminActivitySelect.innerHTML = '<option value="">-- Select an activity --</option>';
      }

      // Populate activities list
      Object.entries(activities).forEach(([name, details]) => {
        const activityCard = document.createElement("div");
        activityCard.className = "activity-card";

        let participantsHTML;
        let spotsLeft;
        
        if (typeof details.participants === 'number') {
          // Non-authenticated or student view
          spotsLeft = details.spots_available;
          participantsHTML = `<p><strong>Participants:</strong> ${details.participants} enrolled</p>`;
        } else {
          // Admin view with full participant list
          spotsLeft = details.max_participants - details.participants.length;
          participantsHTML = details.participants.length > 0
            ? `<div class="participants-section">
                <h5>Participants:</h5>
                <ul class="participants-list">
                  ${details.participants
                    .map(email => 
                      `<li>
                        <span class="participant-email">${email}</span>
                        ${currentUser && (currentUser.role === 'club_admin' || currentUser.role === 'federation_admin') 
                          ? `<button class="delete-btn" data-activity="${name}" data-email="${email}">❌</button>`
                          : ''
                        }
                      </li>`
                    )
                    .join("")}
                </ul>
              </div>`
            : `<p><em>No participants yet</em></p>`;
        }

        activityCard.innerHTML = `
          <h4>${name}</h4>
          <p>${details.description}</p>
          <p><strong>Schedule:</strong> ${details.schedule}</p>
          <p><strong>Availability:</strong> ${spotsLeft} spots left</p>
          <div class="participants-container">
            ${participantsHTML}
          </div>
        `;

        activitiesList.appendChild(activityCard);

        // Add options to select dropdowns
        const option = document.createElement("option");
        option.value = name;
        option.textContent = name;
        activitySelect.appendChild(option);
        
        if (adminActivitySelect) {
          const adminOption = document.createElement("option");
          adminOption.value = name;
          adminOption.textContent = name;
          adminActivitySelect.appendChild(adminOption);
        }
      });

      // Add event listeners to delete buttons (admin only)
      document.querySelectorAll(".delete-btn").forEach((button) => {
        button.addEventListener("click", handleUnregister);
      });
    } catch (error) {
      activitiesList.innerHTML =
        "<p>Failed to load activities. Please try again later.</p>";
      console.error("Error fetching activities:", error);
    }
  }

  async function handleUnregister(event) {
    const button = event.target;
    const activity = button.getAttribute("data-activity");
    const email = button.getAttribute("data-email");

    if (!authToken) {
      showMessage('You must be logged in to perform this action', 'error');
      return;
    }

    try {
      const response = await fetch(
        `/activities/${encodeURIComponent(activity)}/unregister?email=${encodeURIComponent(email)}`,
        {
          method: "DELETE",
          headers: getAuthHeaders()
        }
      );

      const result = await response.json();

      if (response.ok) {
        showMessage(result.message, 'success');
        fetchActivities();
      } else {
        showMessage(result.detail || "An error occurred", 'error');
      }
    } catch (error) {
      showMessage("Failed to unregister. Please try again.", 'error');
      console.error("Error unregistering:", error);
    }
  }

  // Event Listeners
  loginToggleBtn.addEventListener('click', () => openModal(loginModal));
  logoutBtn.addEventListener('click', logout);
  closeLoginModal.addEventListener('click', () => closeModal(loginModal));
  closeRegisterModal.addEventListener('click', () => closeModal(registerModal));
  showRegisterModal.addEventListener('click', () => openModal(registerModal));

  // Close modals when clicking outside
  window.addEventListener('click', (event) => {
    if (event.target === loginModal) {
      closeModal(loginModal);
    } else if (event.target === registerModal) {
      closeModal(registerModal);
    }
  });

  // Login form submission
  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    await login(username, password);
  });

  // Register form submission
  registerForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    
    const userData = {
      email: document.getElementById('reg-email').value,
      username: document.getElementById('reg-username').value,
      full_name: document.getElementById('reg-full-name').value,
      password: document.getElementById('reg-password').value
    };

    try {
      const response = await fetch('/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData)
      });

      const result = await response.json();

      if (response.ok) {
        showMessage('Registration successful! You can now log in.', 'success', registerMessage);
        setTimeout(() => {
          closeModal(registerModal);
          openModal(loginModal);
        }, 2000);
      } else {
        showMessage(result.detail || 'Registration failed', 'error', registerMessage);
      }
    } catch (error) {
      showMessage('Registration failed. Please try again.', 'error', registerMessage);
    }
  });

  // Student signup form
  signupForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!authToken) {
      showMessage('You must be logged in to sign up for activities', 'error');
      return;
    }

    const activity = document.getElementById("activity").value;

    try {
      const response = await fetch(
        `/activities/${encodeURIComponent(activity)}/signup`,
        {
          method: "POST",
          headers: getAuthHeaders()
        }
      );

      const result = await response.json();

      if (response.ok) {
        showMessage(result.message, 'success');
        signupForm.reset();
        fetchActivities();
      } else {
        showMessage(result.detail || "An error occurred", 'error');
      }
    } catch (error) {
      showMessage("Failed to sign up. Please try again.", 'error');
      console.error("Error signing up:", error);
    }
  });

  // Admin signup form
  if (adminSignupForm) {
    adminSignupForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      if (!authToken) {
        showMessage('You must be logged in to perform this action', 'error');
        return;
      }

      const studentEmail = document.getElementById("student-email").value;
      const activity = document.getElementById("admin-activity").value;

      try {
        const response = await fetch(
          `/activities/${encodeURIComponent(activity)}/register-student`,
          {
            method: "POST",
            headers: {
              'Content-Type': 'application/json',
              ...getAuthHeaders()
            },
            body: JSON.stringify({
              activity_name: activity,
              user_email: studentEmail
            })
          }
        );

        const result = await response.json();

        if (response.ok) {
          showMessage(result.message, 'success');
          adminSignupForm.reset();
          fetchActivities();
        } else {
          showMessage(result.detail || "An error occurred", 'error');
        }
      } catch (error) {
        showMessage("Failed to register student. Please try again.", 'error');
        console.error("Error registering student:", error);
      }
    });
  }

  // Initialize app
  checkAuthStatus().then(() => {
    fetchActivities();
  });
});
