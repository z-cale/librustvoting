import SwiftUI
import ComposableArchitecture
import Generated
import UIComponents

struct KeystoneSigningView: View {
    let store: StoreOf<Voting>

    var body: some View {
        WithPerceptionTracking {
            VStack(spacing: 0) {
                Spacer()

                // Simulated Keystone device frame
                VStack(spacing: 0) {
                    // Header
                    HStack {
                        Image(systemName: "lock.shield.fill")
                            .font(.title3)
                        Text("Keystone")
                            .font(.headline)
                    }
                    .foregroundStyle(.white)
                    .padding(.vertical, 12)
                    .frame(maxWidth: .infinity)
                    .background(Color(.darkGray))

                    // Body
                    VStack(spacing: 16) {
                        Text("Approve Voting Delegation")
                            .font(.headline)
                            .padding(.top, 20)

                        VStack(spacing: 8) {
                            detailRow(label: "Amount", value: "0.00 ZEC (shielded)")
                            detailRow(label: "To", value: MockVotingService.hotkeyAddress)
                        }
                        .padding(.horizontal, 16)

                        // Memo
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Memo")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text("Delegating \(store.votingWeightZECString) ZEC voting power for \(store.votingRound.title)")
                                .font(.caption)
                                .padding(12)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color(.systemGray6))
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                        }
                        .padding(.horizontal, 16)

                        Spacer().frame(height: 8)

                        // Buttons
                        HStack(spacing: 16) {
                            Button {
                                store.send(.keystoneRejected)
                            } label: {
                                Text("Reject")
                                    .font(.subheadline.bold())
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 12)
                            }
                            .buttonStyle(.bordered)
                            .tint(.red)

                            Button {
                                store.send(.keystoneApproved)
                            } label: {
                                Text("Approve")
                                    .font(.subheadline.bold())
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 12)
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(.green)
                        }
                        .padding(.horizontal, 16)
                        .padding(.bottom, 20)
                    }
                    .background(Color(.systemBackground))
                }
                .clipShape(RoundedRectangle(cornerRadius: 16))
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color(.systemGray3), lineWidth: 2)
                )
                .padding(.horizontal, 32)

                // Mock label
                HStack(spacing: 6) {
                    Text("MOCK")
                        .font(.system(size: 9, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Color.orange)
                        .clipShape(Capsule())
                    Text("Simulated Keystone screen")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 16)

                Spacer()
            }
            .navigationTitle("Keystone Signing")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button { store.send(.goBack) } label: {
                        Image(systemName: "chevron.left")
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func detailRow(label: String, value: String) -> some View {
        HStack(alignment: .top) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 60, alignment: .leading)
            Text(value)
                .font(.caption.monospaced())
                .lineLimit(1)
                .truncationMode(.middle)
        }
    }
}
