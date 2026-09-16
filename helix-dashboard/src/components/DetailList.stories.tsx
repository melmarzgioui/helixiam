import type { Meta, StoryObj } from "@storybook/react";
import { DetailList, Detail } from "./DetailList";
import { Badge } from "./Badge";

const meta: Meta<typeof DetailList> = {
  title: "Components/DetailList",
  component: DetailList,
  parameters: { layout: "padded" },
};
export default meta;

type Story = StoryObj<typeof DetailList>;

/** The canonical usage: a session-detail readout with a chip, a name+UUID, and split timestamps. */
export const SessionDetail: Story = {
  render: () => (
    <div style={{ maxWidth: 460 }}>
      <DetailList>
        <Detail label="Type" center>
          <Badge tone="success">User</Badge>
        </Detail>
        <Detail label="Identity" mono="c1a848b2-cf68-45d5-85d1-97101cb702a8">
          admin <span className="hx-current-dot"> · current session</span>
        </Detail>
        <Detail label="Realm">master</Detail>
        <Detail label="Signed in" sub="3 Jul 2026, 15:05">
          just now
        </Detail>
        <Detail label="Expires" sub="3 Jul 2026, 15:20">
          in 14m
        </Detail>
        <Detail label="Apps">
          <div className="hx-dl__stack">
            <div>
              <strong>helix-console</strong> <Badge tone="neutral">Browser login</Badge>{" "}
              <span className="hx-badges">
                <Badge tone="accent">openid</Badge> <Badge tone="accent">profile</Badge>
              </span>
            </div>
          </div>
        </Detail>
        <Detail label="Session id" mono="c1a848b2-cf68-45d5-85d1-97101cb702a8" />
      </DetailList>
    </div>
  ),
};

/** Minimal — plain label/value rows. */
export const Simple: Story = {
  render: () => (
    <div style={{ maxWidth: 460 }}>
      <DetailList>
        <Detail label="Name">acme-app</Detail>
        <Detail label="Protocol">OIDC</Detail>
        <Detail label="Status">
          <Badge tone="success">Enabled</Badge>
        </Detail>
      </DetailList>
    </div>
  ),
};
