import { useEffect } from "react";

declare global {
  interface Window {
    google?: any;
    googleTranslateElementInit?: () => void;
  }
}

interface GoogleTranslateProps {
  id?: string;
  className?: string;
}

export function GoogleTranslate({
  id = "google_translate_element",
  className = "",
}: GoogleTranslateProps) {
  useEffect(() => {
    // Define global callback for Google Translate API
    window.googleTranslateElementInit = () => {
      if (window.google?.translate?.TranslateElement) {
        try {
          new window.google.translate.TranslateElement(
            {
              pageLanguage: "en",
              autoDisplay: false,
            },
            id
          );
        } catch (err) {
          console.warn("Google Translate initialization notice:", err);
        }
      }
    };

    // If script is already present in document, trigger callback directly
    if (document.getElementById("google-translate-script")) {
      if (window.google?.translate?.TranslateElement) {
        window.googleTranslateElementInit();
      }
      return;
    }

    // Otherwise inject Google Translate element script
    const script = document.createElement("script");
    script.id = "google-translate-script";
    script.src = "https://translate.google.com/translate_a/element.js?cb=googleTranslateElementInit";
    script.async = true;
    document.body.appendChild(script);
  }, [id]);

  return (
    <div className={`google-translate-wrapper flex items-center ${className}`}>
      <div id={id} className="notranslate" />
    </div>
  );
}
