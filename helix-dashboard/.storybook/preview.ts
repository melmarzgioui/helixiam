import type { Preview } from "@storybook/react";
import "../src/styles/tokens.css";
import "../src/styles/components.css";

/** Theme switcher so every story can be reviewed in light + the Black Cat / Jade dark mode. */
const preview: Preview = {
  parameters: {
    controls: { matchers: { color: /(background|color)$/i, date: /Date$/i } },
    backgrounds: { disable: true }, // theme is driven by the toolbar below, not bg addon
  },
  globalTypes: {
    theme: {
      description: "Brand theme",
      defaultValue: "light",
      toolbar: {
        title: "Theme",
        icon: "circlehollow",
        items: [
          { value: "light", title: "Light" },
          { value: "dark", title: "Dark (Black Cat / Jade)" },
        ],
        dynamicTitle: true,
      },
    },
  },
  decorators: [
    (Story, context) => {
      document.documentElement.setAttribute("data-theme", context.globals.theme);
      document.body.style.background = "var(--bg)";
      document.body.style.padding = "24px";
      return Story();
    },
  ],
};

export default preview;
