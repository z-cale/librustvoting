import SwiftUI
import ComposableArchitecture
import Generated
import UIComponents

struct ProposalDetailView: View {
    let store: StoreOf<Voting>
    let proposal: Proposal

    var body: some View {
        WithPerceptionTracking {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Header
                    VStack(alignment: .leading, spacing: 8) {
                        if let zip = proposal.zipNumber {
                            ZIPBadge(zipNumber: zip)
                        }

                        Text(proposal.title)
                            .zFont(.semiBold, size: 22, style: Design.Text.primary)

                        Text(proposal.description)
                            .zFont(.regular, size: 15, style: Design.Text.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    // Forum link
                    if let url = proposal.forumURL {
                        Link(destination: url) {
                            HStack(spacing: 6) {
                                Image(systemName: "bubble.left.and.text.bubble.right")
                                    .font(.caption)
                                Text("View Forum Discussion")
                                    .zFont(.medium, size: 14, style: Design.Text.link)
                            }
                        }
                    }

                    Spacer().frame(height: 8)

                    // Vote buttons
                    VStack(spacing: 12) {
                        let currentVote = store.votes[proposal.id]

                        voteButton(
                            title: "Support",
                            icon: "hand.thumbsup.fill",
                            color: .green,
                            isSelected: currentVote == .support
                        ) {
                            store.send(.castVote(proposalId: proposal.id, choice: .support))
                        }

                        voteButton(
                            title: "Oppose",
                            icon: "hand.thumbsdown.fill",
                            color: .red,
                            isSelected: currentVote == .oppose
                        ) {
                            store.send(.castVote(proposalId: proposal.id, choice: .oppose))
                        }

                        voteButton(
                            title: "Skip",
                            icon: "forward.fill",
                            color: .gray,
                            isSelected: currentVote == .skip
                        ) {
                            store.send(.castVote(proposalId: proposal.id, choice: .skip))
                        }
                    }

                    Spacer()
                }
                .padding(.horizontal, 24)
                .padding(.top, 16)
            }
            .navigationTitle("Proposal")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        store.send(.backToList)
                    } label: {
                        Image(systemName: "chevron.left")
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func voteButton(
        title: String,
        icon: String,
        color: Color,
        isSelected: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack {
                Image(systemName: icon)
                Text(title)
                    .fontWeight(.semibold)
                Spacer()
                if isSelected {
                    Image(systemName: "checkmark.circle.fill")
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 16)
            .foregroundStyle(isSelected ? .white : color)
            .background(isSelected ? color : color.opacity(0.1))
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .overlay(
                RoundedRectangle(cornerRadius: 14)
                    .stroke(color.opacity(0.3), lineWidth: isSelected ? 0 : 1)
            )
        }
    }
}
