import SwiftUI
import ComposableArchitecture
import Generated
import UIComponents

struct ProposalListView: View {
    @Environment(\.colorScheme) var colorScheme

    let store: StoreOf<Voting>

    var body: some View {
        WithPerceptionTracking {
            VStack(spacing: 0) {
                // ZKP status banner
                if store.delegationProofStatus != .notStarted && store.delegationProofStatus != .complete {
                    ZKPStatusBanner(proofStatus: store.delegationProofStatus)
                        .padding(.horizontal, 24)
                        .padding(.top, 8)
                        .transition(.move(edge: .top).combined(with: .opacity))
                }

                // Progress indicator
                HStack {
                    Text("\(store.votedCount) of \(store.totalProposals) voted")
                        .zFont(.medium, size: 14, style: Design.Text.secondary)

                    Spacer()

                    if store.isDelegationReady {
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                                .font(.system(size: 12))
                            Text("Delegation ready")
                                .font(.system(size: 12, weight: .medium))
                                .foregroundStyle(.green)
                        }
                    }
                }
                .padding(.horizontal, 24)
                .padding(.top, 16)
                .padding(.bottom, 8)

                // Proposal cards
                ScrollView {
                    LazyVStack(spacing: 12) {
                        ForEach(store.votingRound.proposals) { proposal in
                            proposalCard(proposal)
                                .onTapGesture {
                                    store.send(.proposalTapped(proposal.id))
                                }
                        }
                    }
                    .padding(.horizontal, 24)
                    .padding(.bottom, 100) // Space for floating button
                }

                // Floating review button
                VStack {
                    ZashiButton(
                        "Review & Submit",
                        type: store.canSubmitVotes ? .primary : .quaternary
                    ) {
                        store.send(.reviewVotesTapped)
                    }
                    .disabled(!store.canSubmitVotes)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 12)
                    .background {
                        LinearGradient(
                            colors: [
                                Design.Surfaces.bgPrimary.color(colorScheme).opacity(0),
                                Design.Surfaces.bgPrimary.color(colorScheme),
                            ],
                            startPoint: .top,
                            endPoint: UnitPoint(x: 0.5, y: 0.3)
                        )
                    }
                }
            }
            .navigationTitle(store.votingRound.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        store.send(.goBack)
                    } label: {
                        Image(systemName: "chevron.left")
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func proposalCard(_ proposal: Proposal) -> some View {
        let vote = store.votes[proposal.id]

        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    if let zip = proposal.zipNumber {
                        ZIPBadge(zipNumber: zip)
                    }
                    Text(proposal.title)
                        .zFont(.semiBold, size: 16, style: Design.Text.primary)
                }

                Spacer()

                VoteChip(choice: vote)
            }

            Text(proposal.description)
                .zFont(.regular, size: 13, style: Design.Text.secondary)
                .lineLimit(2)
        }
        .padding(16)
        .background(Design.Surfaces.bgPrimary.color(colorScheme))
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(
                    vote != nil ? voteColor(vote).opacity(0.3) : Design.Surfaces.strokeSecondary.color(colorScheme),
                    lineWidth: 1
                )
        )
        .shadow(color: .black.opacity(0.04), radius: 2, x: 0, y: 1)
    }

    private func voteColor(_ vote: VoteChoice?) -> Color {
        guard let vote else { return .clear }
        switch vote {
        case .support: return .green
        case .oppose: return .red
        case .skip: return .gray
        }
    }
}
