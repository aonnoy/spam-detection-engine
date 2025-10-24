// ============================================================================
// UNIVERSAL CLOUDFLARE TURNSTILE FORM HANDLER - YOUTUBE TUTORIAL VERSION
// ============================================================================
// Generic spam detection system that works with ANY form structure
// Users define field types and data expectations using HTML attributes
//
// REQUIRED ATTRIBUTES:
// - cf-form="unique-id" (on form element)
// - cf-form-purpose="description of form purpose for AI context"
// - cf-turnstile-sitekey="your-site-key"
// - cf-form-url="https://your-form-handler.com"
// - cf-field-type="field-type" (on each input)
// - cf-field-data="expected data description" (on each input)
// ============================================================================

// ========================================
// CONFIGURATION - Modify these as needed
// ========================================
const FORM_CONFIG = {
  // Worker URL - Update this to your deployed worker
  workerUrl: "https://spam-detection-engine.hello-be0.workers.dev/",

  // Form Selectors & Attributes
  formSelector: "form[cf-form]",
  formIdAttribute: "cf-form",
  formPurposeAttribute: "cf-form-purpose",
  siteKeyAttribute: "cf-turnstile-sitekey",
  // Field Type Attributes
  fieldTypeAttribute: "cf-field-type",
  fieldDataAttribute: "cf-field-data",

  // Submit Button Selectors
  submitButtonSelector: '[cf-form-submit="trigger"]',
  submitLabelSelector: '[cf-form-submit="button-label"]',

  // Error Handling Selectors
  errorElementSelector: '[cf-form-submit="error"]',
  errorTextSelector: '[cf-form-submit="error-text"]',

  // Success Element Selector
  successElementSelector: '[cf-form-submit="success"]',

  // CSS Classes
  hideClass: "hide",
  turnstileContainerClass: "cf-turnstile-container",

  // Turnstile Settings
  turnstileTheme: "light",
  turnstileSize: "normal",

  // Loading Text
  loadingText: "Sending...",

  // Honeypot Settings
  enableHoneypot: true,
  honeypotFieldNames: [
    "honeypot_website",
    "honeypot_url",
    "honeypot_company_site",
    "honeypot_business_url",
    "bot_trap_website",
    "bot_trap_url",
    "spam_trap_site",
    "spam_trap_link",
  ],

  // Page URL Field
  pageUrlField: {
    enabled: true,
    fieldName: "Page URL",
  },
};

class UniversalFormSecurityHandler {
  constructor() {
    this.forms = [];
    this.workerUrl = FORM_CONFIG.workerUrl;
    this.init();
  }

  init() {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => this.setupForms());
    } else {
      this.setupForms();
    }
  }

  setupForms() {
    // Find all forms with cf-form attribute
    const formElements = document.querySelectorAll(FORM_CONFIG.formSelector);
    console.log(`Universal Form Security: Found ${formElements.length} forms`);

    formElements.forEach((formElement) => {
      this.setupSingleForm(formElement);
    });
  }

  setupSingleForm(formElement) {
    // Extract configuration from custom attributes
    const config = {
      formId: formElement.getAttribute(FORM_CONFIG.formIdAttribute),
      formPurpose: formElement.getAttribute(FORM_CONFIG.formPurposeAttribute),
      siteKey: formElement.getAttribute(FORM_CONFIG.siteKeyAttribute),
      formElement: formElement,
      submitButton: formElement.querySelector(FORM_CONFIG.submitButtonSelector),
      submitLabel: formElement.querySelector(FORM_CONFIG.submitLabelSelector),
      errorElement: formElement.querySelector(FORM_CONFIG.errorElementSelector),
      errorText: formElement.querySelector(FORM_CONFIG.errorTextSelector),
      successElement: document.querySelector(
        FORM_CONFIG.successElementSelector
      ),
      turnstileToken: null,
    };

    // Validate required attributes
    if (!config.siteKey || !config.formPurpose) {
      console.error("Universal Form Security: Missing required attributes", {
        formId: config.formId,
        hasSiteKey: !!config.siteKey,
        hasFormPurpose: !!config.formPurpose,
      });
      return;
    }

    // Validate field configurations
    const fieldValidation = this.validateFieldConfiguration(formElement);
    if (!fieldValidation.valid) {
      console.error(
        "Universal Form Security: Invalid field configuration",
        fieldValidation.errors
      );
      return;
    }

    console.log(`Universal Form Security: Setting up form "${config.formId}"`, {
      purpose: config.formPurpose,
      fieldsConfigured: fieldValidation.configuredFields,
    });

    // Store form config
    this.forms.push(config);

    // Setup honeypot field
    this.setupHoneypot(config);

    // Setup Page URL field
    this.setupPageUrlField(config);

    // Setup Turnstile and form submission
    this.loadTurnstile(() => this.renderTurnstile(config));
    this.setupFormSubmission(config);
  }

  validateFieldConfiguration(formElement) {
    const fields = formElement.querySelectorAll(
      `[${FORM_CONFIG.fieldTypeAttribute}]`
    );
    const configuredFields = [];
    const errors = [];

    fields.forEach((field) => {
      const fieldType = field.getAttribute(FORM_CONFIG.fieldTypeAttribute);
      const fieldData = field.getAttribute(FORM_CONFIG.fieldDataAttribute);
      const fieldName = field.name || field.getAttribute("name");

      if (!fieldType) {
        errors.push(
          `Field "${fieldName}" missing ${FORM_CONFIG.fieldTypeAttribute} attribute`
        );
      }

      if (
        !fieldData &&
        fieldType !== "ignore" &&
        fieldType !== "system-metadata"
      ) {
        errors.push(
          `Field "${fieldName}" missing ${FORM_CONFIG.fieldDataAttribute} attribute`
        );
      }

      if (!fieldName) {
        errors.push(`Field with type "${fieldType}" missing name attribute`);
      }

      configuredFields.push({
        name: fieldName,
        type: fieldType,
        data: fieldData,
      });
    });

    return {
      valid: errors.length === 0,
      errors: errors,
      configuredFields: configuredFields,
    };
  }

  setupHoneypot(config) {
    if (!FORM_CONFIG.enableHoneypot) {
      return;
    }

    // Check if honeypot already exists
    const existingHoneypot = config.formElement.querySelector(
      'input[data-honeypot="true"]'
    );
    if (existingHoneypot) {
      return;
    }

    // Create honeypot field with random name
    const randomFieldName =
      FORM_CONFIG.honeypotFieldNames[
        Math.floor(Math.random() * FORM_CONFIG.honeypotFieldNames.length)
      ];

    const honeypotField = document.createElement("input");
    honeypotField.type = "text";
    honeypotField.name = randomFieldName;
    honeypotField.setAttribute("data-honeypot", "true");
    honeypotField.setAttribute("tabindex", "-1");
    honeypotField.setAttribute("autocomplete", "off");

    // Make it invisible but accessible to screen readers
    honeypotField.style.cssText = `
        position: absolute !important;
        left: -9999px !important;
        top: -9999px !important;
        width: 1px !important;
        height: 1px !important;
        opacity: 0 !important;
        pointer-events: none !important;
      `;

    // Add aria-hidden for screen readers
    honeypotField.setAttribute("aria-hidden", "true");

    // Insert at the beginning of the form
    config.formElement.insertBefore(
      honeypotField,
      config.formElement.firstChild
    );

    console.log(
      `Universal Form Security: Added honeypot field "${randomFieldName}"`
    );
  }

  setupPageUrlField(config) {
    if (!FORM_CONFIG.pageUrlField.enabled) {
      return;
    }

    // Check if Page URL field already exists
    const existingPageUrlField = config.formElement.querySelector(
      `input[name="${FORM_CONFIG.pageUrlField.fieldName}"]`
    );
    if (existingPageUrlField) {
      // Update existing field
      existingPageUrlField.value = window.location.href;
      return;
    }

    // Create Page URL hidden field
    const pageUrlField = document.createElement("input");
    pageUrlField.type = "hidden";
    pageUrlField.name = FORM_CONFIG.pageUrlField.fieldName;
    pageUrlField.value = window.location.href;
    pageUrlField.setAttribute("data-page-url", "true");
    pageUrlField.setAttribute(
      FORM_CONFIG.fieldTypeAttribute,
      "system-metadata"
    );

    // Insert at the beginning of the form
    config.formElement.insertBefore(
      pageUrlField,
      config.formElement.firstChild
    );
  }

  loadTurnstile(callback) {
    if (!window.turnstile) {
      const script = document.createElement("script");
      script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
      script.async = true;
      script.defer = true;
      script.onload = callback;
      document.head.appendChild(script);
    } else {
      callback();
    }
  }

  renderTurnstile(config) {
    // Create container for Turnstile widget
    let turnstileContainer = config.formElement.querySelector(
      `.${FORM_CONFIG.turnstileContainerClass}`
    );
    if (!turnstileContainer) {
      turnstileContainer = document.createElement("div");
      turnstileContainer.className = FORM_CONFIG.turnstileContainerClass;
      turnstileContainer.style.marginBottom = "20px";

      // Insert before submit button
      if (config.submitButton) {
        config.submitButton.parentNode.insertBefore(
          turnstileContainer,
          config.submitButton
        );
      } else {
        // Fallback: append to form
        config.formElement.appendChild(turnstileContainer);
      }
    }

    // Render Turnstile widget and store the widget ID
    config.turnstileWidgetId = window.turnstile.render(turnstileContainer, {
      sitekey: config.siteKey,
      callback: (token) => {
        config.turnstileToken = token;
        this.enableSubmitButton(config);
        console.log("Universal Form Security: Turnstile token received");
      },
      "error-callback": () => {
        config.turnstileToken = null;
        this.disableSubmitButton(config);
        this.showError(
          config,
          "Security verification failed. Please try again."
        );
        console.error("Universal Form Security: Turnstile error");
      },
      "expired-callback": () => {
        config.turnstileToken = null;
        this.disableSubmitButton(config);
        console.log("Universal Form Security: Turnstile token expired");
      },
      theme: FORM_CONFIG.turnstileTheme,
      size: FORM_CONFIG.turnstileSize,
    });

    // Initially disable submit button
    this.disableSubmitButton(config);
  }

  setupFormSubmission(config) {
    config.formElement.addEventListener("submit", (e) => {
      // Let native validation run first
      if (!config.formElement.checkValidity()) {
        return; // Let browser show validation errors
      }

      // Form is valid, now intercept
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();

      this.handleFormSubmit(config);
    });

    // Also prevent any other form submission events
    config.formElement.addEventListener(
      "submit",
      (e) => {
        e.preventDefault();
      },
      true
    ); // Use capture phase
  }

  async handleFormSubmit(config) {
    console.log("Universal Form Security: Form submission started");

    // Clear any previous errors
    this.hideError(config);

    // Validate Turnstile token
    if (!config.turnstileToken) {
      this.showError(config, "Please complete the security verification.");
      return;
    }

    // Set loading state
    this.setSubmitButtonLoading(config, true);

    try {
      // Collect form data with field type information
      const formData = this.collectFormData(config);

      // Add metadata for spam detection
      formData.metadata = {
        submissionTime: Date.now(),
        pageLoadTime: window.performance.timing.loadEventEnd,
        userAgent: navigator.userAgent,
        referrer: document.referrer,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        formId: config.formId,
        formPurpose: config.formPurpose,
      };

      const payload = {
        turnstileToken: config.turnstileToken,
        formData: formData,
        fieldTypes: formData.fieldTypes, // Include field type information
        formPurpose: config.formPurpose,
      };

      console.log("Universal Form Security: Sending to worker", {
        formId: config.formId,
        fieldCount: Object.keys(formData).length - 2, // Exclude metadata and fieldTypes
        hasFieldTypes: !!formData.fieldTypes,
      });

      // Submit to Cloudflare Worker
      const response = await fetch(this.workerUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const result = await response.json();

      if (result.success) {
        console.log("Universal Form Security: Form submitted successfully");
        this.handleSuccess(config);
      } else {
        console.log(
          "Universal Form Security: Form submission blocked",
          result.error
        );

        // Reset Turnstile on error to generate new token
        this.resetTurnstileOnError(config);

        this.showError(
          config,
          result.error?.message || "Something went wrong. Please try again."
        );
      }
    } catch (error) {
      console.error("Universal Form Security: Network error", error);

      // Reset Turnstile on error to generate new token
      this.resetTurnstileOnError(config);

      this.showError(
        config,
        "Network error. Please check your connection and try again."
      );
    } finally {
      this.setSubmitButtonLoading(config, false);
    }
  }

  collectFormData(config) {
    const formData = {};
    const fieldTypes = {};
    const fieldDataDescriptions = {};

    const inputs = config.formElement.querySelectorAll(
      "input, textarea, select"
    );

    inputs.forEach((input) => {
      if (input.name && input.type !== "submit") {
        // Collect field value
        if (input.type === "checkbox") {
          formData[input.name] = input.checked;
        } else if (input.type === "radio") {
          if (input.checked) {
            formData[input.name] = input.value;
          }
        } else {
          formData[input.name] = input.value;
        }

        // Collect field type information
        const fieldType = input.getAttribute(FORM_CONFIG.fieldTypeAttribute);
        const fieldData = input.getAttribute(FORM_CONFIG.fieldDataAttribute);

        if (fieldType) {
          fieldTypes[input.name] = fieldType;
        }

        if (fieldData) {
          fieldDataDescriptions[input.name] = fieldData;
        }
      }
    });

    // Add honeypot detection metadata
    if (FORM_CONFIG.enableHoneypot) {
      const honeypotField = config.formElement.querySelector(
        'input[data-honeypot="true"]'
      );
      if (honeypotField) {
        formData._honeypot_field_name = honeypotField.name;
        formData._honeypot_filled = honeypotField.value !== "";
      }
    }

    // Add field type information to form data
    formData.fieldTypes = fieldTypes;
    formData.fieldDataDescriptions = fieldDataDescriptions;

    console.log("Universal Form Security: Collected form data", {
      fieldCount: Object.keys(formData).length - 3, // Exclude metadata, fieldTypes, fieldDataDescriptions
      configuredFields: Object.keys(fieldTypes).length,
      hasHoneypot: !!formData._honeypot_field_name,
    });

    return formData;
  }

  resetTurnstileOnError(config) {
    if (window.turnstile) {
      try {
        // Reset the Turnstile widget to generate a new token
        if (config.turnstileWidgetId) {
          window.turnstile.reset(config.turnstileWidgetId);
        } else {
          window.turnstile.reset();
        }

        console.log("Universal Form Security: Turnstile reset successful");
      } catch (error) {
        console.warn("Universal Form Security: Turnstile reset failed", error);
      }

      // Clear the current token and disable submit button until new token received
      config.turnstileToken = null;
      this.disableSubmitButton(config);

      // Re-render turnstile if it seems stuck
      setTimeout(() => {
        if (!config.turnstileToken) {
          console.log(
            "Universal Form Security: Re-rendering Turnstile after reset"
          );
          this.renderTurnstile(config);
        }
      }, 1000);
    }
  }

  enableSubmitButton(config) {
    if (config.submitButton) {
      config.submitButton.disabled = false;
      config.submitButton.style.opacity = "1";
    }
  }

  disableSubmitButton(config) {
    if (config.submitButton) {
      config.submitButton.disabled = true;
      config.submitButton.style.opacity = "0.6";
    }
  }

  setSubmitButtonLoading(config, loading) {
    if (!config.submitButton) return;

    if (loading) {
      config.submitButton.disabled = true;
      if (config.submitLabel) {
        config.originalButtonText = config.submitLabel.innerHTML;
        config.submitLabel.innerHTML = FORM_CONFIG.loadingText;
      }
    } else {
      config.submitButton.disabled = false;
      if (config.submitLabel && config.originalButtonText) {
        config.submitLabel.innerHTML = config.originalButtonText;
      }
    }
  }

  showError(config, message) {
    // Use the configured error elements
    if (config.errorElement && config.errorText) {
      // Set the error message
      config.errorText.textContent = message;

      // Remove hide class to show error
      config.errorElement.classList.remove(FORM_CONFIG.hideClass);
    } else {
      // Fallback: alert (not ideal but ensures user sees error)
      console.error(
        "Universal Form Security: No error display configured, using alert"
      );
      alert(message);
    }
  }

  hideError(config) {
    // Use the configured error elements
    if (config.errorElement) {
      // Add hide class to hide error
      config.errorElement.classList.add(FORM_CONFIG.hideClass);
    }
  }

  handleSuccess(config) {
    console.log("Universal Form Security: Form submission successful");

    // Hide the form
    config.formElement.style.display = "none";

    // Show success element if it exists
    if (config.successElement) {
      config.successElement.style.display = "block";
      console.log("Universal Form Security: Success message displayed");
    } else {
      console.warn(
        'Universal Form Security: No success element found with cf-form-submit="success"'
      );
    }

    // Reset Turnstile for potential reuse
    if (window.turnstile) {
      window.turnstile.reset();
    }
    config.turnstileToken = null;
  }
}

// Initialize when page loads
console.log("Universal Form Security: Initializing...");
new UniversalFormSecurityHandler();
