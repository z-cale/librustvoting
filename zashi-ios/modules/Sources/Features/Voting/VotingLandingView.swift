import SwiftUI
import ComposableArchitecture
import Generated
import UIComponents

struct VotingLandingView: View {
    @Environment(\.colorScheme) var colorScheme

    let store: StoreOf<Voting>

    var body: some View {
        WithPerceptionTracking {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    PrototypeBanner()

                    // Round info card
                    VStack(alignment: .leading, spacing: 16) {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(store.votingRound.title)
                                    .zFont(.semiBold, size: 22, style: Design.Text.primary)
                                Text("\(store.votingRound.daysRemaining) days remaining")
                                    .zFont(.medium, size: 14, style: Design.Text.secondary)
                            }
                            Spacer()
                            Image(systemName: "checkmark.shield.fill")
                                .font(.title)
                                .foregroundStyle(Design.Surfaces.brandPrimary.color(colorScheme))
                        }

                        Text(store.votingRound.description)
                            .zFont(.regular, size: 15, style: Design.Text.secondary)
                            .fixedSize(horizontal: false, vertical: true)

                        Divider()

                        // Details grid
                        VStack(spacing: 12) {
                            detailRow(
                                label: "Proposals",
                                value: "\(store.votingRound.proposals.count)"
                            )
                            detailRow(
                                label: "Snapshot Height",
                                value: "#\(store.votingRound.snapshotHeight.formatted())"
                            )
                            detailRow(
                                label: "Voting Ends",
                                value: store.votingRound.votingEnd.formatted(date: .abbreviated, time: .omitted)
                            )
                        }
                    }
                    .padding(20)
                    .background(Design.Surfaces.bgPrimary.color(colorScheme))
                    .clipShape(RoundedRectangle(cornerRadius: 16))
                    .overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(Design.Surfaces.strokeSecondary.color(colorScheme), lineWidth: 1)
                    )
                    .shadow(color: .black.opacity(0.04), radius: 3, x: 0, y: 2)

                    // Voting weight card
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Your Voting Weight")
                            .zFont(.medium, size: 14, style: Design.Text.tertiary)

                        HStack(alignment: .firstTextBaseline, spacing: 4) {
                            Text(store.votingWeightZECString)
                                .zFont(.semiBold, size: 28, style: Design.Text.primary)
                            Text("ZEC")
                                .zFont(.medium, size: 16, style: Design.Text.secondary)
                        }

                        Text("Based on your shielded balance at snapshot height")
                            .zFont(.regular, size: 13, style: Design.Text.tertiary)
                    }
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Design.Surfaces.bgPrimary.color(colorScheme))
                    .clipShape(RoundedRectangle(cornerRadius: 16))
                    .overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(Design.Surfaces.strokeSecondary.color(colorScheme), lineWidth: 1)
                    )

                    // CTA
                    ZashiButton("Set Up Voting", type: .primary) {
                        store.send(.beginVotingTapped)
                    }

                    if store.isKeystoneUser {
                        HStack(spacing: 6) {
                            Image(systemName: "lock.shield")
                                .font(.caption)
                            Text("Keystone hardware signing required")
                                .font(.caption)
                        }
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                    }

                    Spacer()
                }
                .screenHorizontalPadding()
                .padding(.top, 16)
            }
            .navigationTitle("Governance")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        store.send(.dismissFlow)
                    } label: {
                        Image(systemName: "xmark")
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func detailRow(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .zFont(.regular, size: 14, style: Design.Text.tertiary)
            Spacer()
            Text(value)
                .zFont(.medium, size: 14, style: Design.Text.primary)
        }
    }
}
