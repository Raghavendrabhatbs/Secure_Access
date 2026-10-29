<script lang="ts">
    import {
        faCalendarCheck,
        faCalendarXmark,
        faSquareCheck,
        faSquareXmark,
    } from '@fortawesome/free-solid-svg-icons'
    import {
        Alert,
        Button,
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
        FormGroup,
        Modal,
        ModalBody,
        ModalFooter,
        ModalHeader,
    } from '@sveltestrap/sveltestrap'
    import {
        api,
        type Ticket,
        type TicketRequest,
        TicketRequestStatus,
        updateTicketMetadata,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import { parseLocalTicketExpiry } from 'admin/lib/ticketExpiry'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { formatDurationAsHumantime } from 'common/duration'
    import EmptyState from 'common/EmptyState.svelte'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import RelativeDate from 'common/RelativeDate.svelte'
    import { statusColor, statusIcon } from 'common/ticketRequestStatus'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'

    let error: string | undefined = $state()
    let success: string | undefined = $state()
    let tickets: Ticket[] | undefined = $state()
    let requests: TicketRequest[] | undefined = $state()
    let requestHistoryFilter: TicketRequestStatus | undefined = $state()
    let userMap: Map<string, string> = $state(new Map())
    let targetMap: Map<string, string> = $state(new Map())

    let denyModalRequest: TicketRequest | undefined = $state()
    let denyReason = $state('')
    let denyError: string | undefined = $state()
    let editingTicket: Ticket | undefined = $state()
    let editDescription = $state('')
    let editExpiry = $state('')
    let editExpiryMode: 'set' | 'none' = $state('none')
    let editUsesLeft = $state('')
    let editError: string | undefined = $state()
    let savingEdit = $state(false)
    let currentTime = $state(Date.now())
    const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'local time'

    $effect(() => {
        const timer = setInterval(() => {
            currentTime = Date.now()
        }, 1000)
        return () => clearInterval(timer)
    })

    function isTicketExpired(ticket: Ticket): boolean {
        return !!ticket.expiry && new Date(ticket.expiry).getTime() <= currentTime
    }

    function ticketStatus(ticket: Ticket): string {
        if (isTicketExpired(ticket)) {
            return 'Expired'
        }
        if (ticket.usesLeft === 0) {
            return 'Exhausted'
        }
        return 'Active'
    }

    let pendingRequests = $derived(
        requests?.filter(r => r.status === TicketRequestStatus.Pending) ?? [],
    )
    let filteredHistory = $derived.by(() => {
        if (!requests) {
            return []
        }
        const nonPending = requests.filter(
            r => r.status !== TicketRequestStatus.Pending,
        )
        if (!requestHistoryFilter) {
            return nonPending
        }
        return nonPending.filter(r => r.status === requestHistoryFilter)
    })

    async function loadTickets() {
        tickets = await api.getTickets()
    }

    async function loadRequests() {
        if (!$adminPermissions.ticketRequestsManage) {
            return
        }
        requests = await api.getTicketRequests({})
    }

    async function loadLookups() {
        const [users, targets] = await Promise.all([
            api.getUsers({}),
            api.getTargets({}),
        ])
        userMap = new Map(users.map(u => [u.id, u.username]))
        targetMap = new Map(targets.map(t => [t.id, t.name]))
    }

    async function load() {
        await Promise.all([loadTickets(), loadRequests(), loadLookups()])
    }

    const initPromise = load()

    async function deleteTicket(ticket: Ticket) {
        if (!confirm(`Delete this ticket for ${ticket.username} to ${ticket.target}?`)) {
            return
        }
        error = undefined
        try {
            await api.deleteTicket({ id: ticket.id })
            await loadTickets()
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    function openTicketEditor(ticket: Ticket) {
        editingTicket = ticket
        editDescription = ticket.description
        if (ticket.expiry) {
            editExpiryMode = 'set'
            const localExpiry = new Date(ticket.expiry)
            localExpiry.setMinutes(
                localExpiry.getMinutes() - localExpiry.getTimezoneOffset(),
            )
            editExpiry = localExpiry.toISOString().slice(0, 16)
        } else {
            editExpiryMode = 'none'
            editExpiry = ''
        }
        editUsesLeft = ticket.usesLeft == null ? '' : String(ticket.usesLeft)
        editError = undefined
    }

    async function saveTicketMetadata() {
        if (!editingTicket) {
            return
        }
        const usesLeft = editUsesLeft === '' ? undefined : Number(editUsesLeft)
        if (usesLeft !== undefined && (!Number.isInteger(usesLeft) || usesLeft < 0)) {
            editError = 'Uses remaining must be a non-negative whole number, or blank for unlimited.'
            return
        }

        let expiry: Date | undefined
        if (editExpiryMode === 'set') {
            try {
                expiry = parseLocalTicketExpiry(editExpiry)
            } catch (err) {
                editError = err instanceof Error ? err.message : String(err)
                return
            }
        }

        savingEdit = true
        editError = undefined
        try {
            await updateTicketMetadata(editingTicket.id, {
                description: editDescription,
                expiry,
                numberOfUses: usesLeft,
            })
            editingTicket = undefined
            await loadTickets()
        } catch (err) {
            editError = await stringifyError(err)
            throw err
        } finally {
            savingEdit = false
        }
    }

    async function approve(request: TicketRequest) {
        error = undefined
        success = undefined
        try {
            const result = await api.approveTicketRequest({ id: request.id })
            const userName = userMap.get(result.userId) ?? result.userId
            const targetName = targetMap.get(result.targetId) ?? result.targetId
            success = `Approved ticket request for ${userName} to ${targetName}. An Admin must issue the ticket separately.`
            await loadRequests()
        } catch (err) {
            error = await stringifyError(err)
            throw err
        }
    }

    async function deny() {
        if (!denyModalRequest) {
            return
        }
        denyError = undefined
        success = undefined
        try {
            await api.denyTicketRequest({
                id: denyModalRequest.id,
                denyTicketRequestBody: {
                    reason: denyReason || undefined,
                },
            })
            success = `Denied ticket request from ${userMap.get(denyModalRequest.userId) ?? denyModalRequest.userId}.`
            denyModalRequest = undefined
            denyReason = ''
            await loadRequests()
        } catch (err) {
            denyError = await stringifyError(err)
            throw err
        }
    }
</script>

<div class="container-max-lg">
    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    {#if success}
        <Alert color="success">{success}</Alert>
    {/if}

    <div class="page-summary-bar">
        <h1>Tickets</h1>
        <a
            class="btn btn-primary ms-auto"
            href="/config/tickets/create"
            class:disabled={!$adminPermissions.ticketsCreate}
            use:link
        >
            Create a ticket
        </a>
    </div>

    <Loadable promise={initPromise}>
        {#if $adminPermissions.ticketRequestsManage && pendingRequests.length}
            <h5 class="mt-4 mb-3">
                Pending requests
                <span class="badge bg-warning text-dark"
                    >{pendingRequests.length}</span
                >
            </h5>
            <div class="list-group list-group-flush mb-4">
                {#each pendingRequests as request (request.id)}
                    <div class="list-group-item gap-3">
                        <span
                            class={statusColor(request.status)}
                            title={request.status}
                        >
                            <Fa icon={statusIcon(request.status)} fw />
                        </span>
                        <div class="me-auto">
                            <strong>
                                {userMap.get(request.userId) ?? request.userId}
                                &rarr;
                                {targetMap.get(request.targetId) ?? request.targetId}
                            </strong>
                            {#if request.description}
                                <small class="d-block text-muted"
                                    >{request.description}</small
                                >
                            {/if}
                            {#if request.requestedDurationSeconds}
                                <small class="d-block text-muted">
                                    Duration:
                                    {formatDurationAsHumantime(request.requestedDurationSeconds)}
                                </small>
                            {/if}
                        </div>
                        <small class="text-muted mx-3">
                            <RelativeDate date={request.created} />
                        </small>
                        <div class="d-flex gap-1">
                            <AsyncButton
                                color="success"
                                class="me-1"
                                click={() => approve(request)}
                            >
                                Approve
                            </AsyncButton>
                            <Button
                                color="danger"
                                onclick={() => {
                            denyModalRequest = request
                            denyReason = ''
                            denyError = undefined
                        }}
                            >
                                Deny
                            </Button>
                        </div>
                    </div>
                {/each}
            </div>
        {/if}

        {#if tickets}
            <h5 class="mt-4 mb-3">
                Tickets
                {#if tickets.length}
                    <span class="badge bg-secondary">{tickets.length}</span>
                {/if}
            </h5>
            {#if tickets.length}
                <div class="list-group list-group-flush mb-4">
                    {#each tickets as ticket (ticket.id)}
                        <div class="list-group-item gap-3">
                            <div>
                                <small class="d-block font-monospace text-muted">
                                    {ticket.id}
                                </small>
                                <strong>
                                    Access to {ticket.target} as
                                    {ticket.username}
                                </strong>
                                <span class="badge bg-secondary ms-2">
                                    {ticket.protocol}
                                </span>
                                <span
                                    class:bg-danger={ticketStatus(ticket) === 'Expired'}
                                    class:bg-warning={ticketStatus(ticket) === 'Exhausted'}
                                    class:bg-success={ticketStatus(ticket) === 'Active'}
                                    class="badge ms-2"
                                >
                                    {ticketStatus(ticket)}
                                </span>
                                {#if ticket.selfService}
                                    <span class="badge bg-info ms-2">
                                        self-service
                                    </span>
                                {/if}
                                {#if ticket.description}
                                    <small class="d-block text-muted">
                                        {ticket.description}
                                    </small>
                                {/if}
                                {#if ticket.expiry}
                                    <small
                                        class="text-muted d-flex align-items-center gap-2"
                                    >
                                        <Fa
                                            icon={isTicketExpired(ticket) ? faCalendarXmark : faCalendarCheck}
                                        />
                                        {isTicketExpired(ticket) ? 'Expired' : 'Expires'}
                                        {ticket.expiry.toLocaleString()} ({timeZone})
                                    </small>
                                {:else}
                                    <small class="text-muted d-block">No Expiry</small>
                                {/if}
                            </div>
                            {#if ticket.usesLeft != null}
                                {#if ticket.usesLeft > 0}
                                    <small
                                        class="text-muted d-flex align-items-center gap-2"
                                    >
                                        <Fa icon={faSquareCheck} />
                                        Uses left: {ticket.usesLeft}
                                    </small>
                                {/if}
                                {#if ticket.usesLeft === 0}
                                    <small
                                        class="text-danger d-flex align-items-center gap-2"
                                    >
                                        <Fa icon={faSquareXmark} />
                                        Used up
                                    </small>
                                {/if}
                            {/if}
                            <small class="text-muted ms-auto text-end">
                                Created {ticket.created.toLocaleString()} ({timeZone})
                            </small>
                            <Dropdown>
                                <DropdownToggle
                                    class="ticket-actions-toggle"
                                    aria-label={`Actions for ticket to ${ticket.target} as ${ticket.username}`}
                                    title="Actions"
                                    caret={false}
                                    disabled={!$adminPermissions.ticketsCreate && !$adminPermissions.ticketsDelete}
                                >
                                    ⋯
                                </DropdownToggle>
                                <DropdownMenu end>
                                    <DropdownItem
                                        onclick={() => openTicketEditor(ticket)}
                                        disabled={!$adminPermissions.ticketsCreate}
                                    >
                                        Edit
                                    </DropdownItem>
                                    <DropdownItem
                                        class="text-danger"
                                        onclick={() => deleteTicket(ticket)}
                                        disabled={!$adminPermissions.ticketsDelete}
                                    >
                                        Delete
                                    </DropdownItem>
                                </DropdownMenu>
                            </Dropdown>
                        </div>
                    {/each}
                </div>
            {:else}
                <EmptyState
                    title="No tickets"
                    hint="Tickets are secret keys that allow access to one specific target without any additional authentication"
                />
            {/if}
        {/if}

        {#if $adminPermissions.ticketRequestsManage && requests}
            <h5 class="mt-4 mb-3 d-flex align-items-center">
                Request history
                <FormGroup class="ms-auto mb-0">
                    <select
                        class="form-control form-control-sm"
                        value={requestHistoryFilter ?? ''}
                        onchange={e => {
                    const v = e.currentTarget.value
                    requestHistoryFilter = v ? v as TicketRequestStatus : undefined
                }}
                    >
                        <option value="">All</option>
                        <option value={TicketRequestStatus.Approved}>
                            Approved
                        </option>
                        <option value={TicketRequestStatus.Denied}>
                            Denied
                        </option>
                    </select>
                </FormGroup>
            </h5>
            {#if filteredHistory.length || requestHistoryFilter}
                <div class="list-group list-group-flush">
                    {#each filteredHistory as request (request.id)}
                        <div class="list-group-item">
                            <span
                                class={statusColor(request.status)}
                                title={request.status}
                            >
                                <Fa icon={statusIcon(request.status)} fw />
                            </span>
                            <div class="ms-2 me-auto">
                                <strong>
                                    {userMap.get(request.userId) ?? request.userId}
                                    &rarr;
                                    {targetMap.get(request.targetId) ?? request.targetId}
                                </strong>
                                {#if request.description}
                                    <small class="d-block text-muted"
                                        >{request.description}</small
                                    >
                                {/if}
                                {#if request.requestedDurationSeconds}
                                    <small class="d-block text-muted">
                                        Duration:
                                        {formatDurationAsHumantime(request.requestedDurationSeconds)}
                                    </small>
                                {/if}
                                {#if request.resolvedByUserId}
                                    <small class="d-block text-muted">
                                        {request.status === TicketRequestStatus.Approved ? 'Approved' : 'Denied'}
                                        by
                                        {userMap.get(request.resolvedByUserId) ?? request.resolvedByUserId}
                                    </small>
                                {/if}
                                {#if request.status === TicketRequestStatus.Approved && !request.ticketId}
                                    <small class="d-block text-info">
                                        Awaiting user activation
                                    </small>
                                {/if}
                                {#if request.denyReason}
                                    <small class="d-block text-danger">
                                        Reason: {request.denyReason}
                                    </small>
                                {/if}
                            </div>
                            <small class="text-muted mx-3">
                                <RelativeDate date={request.created} />
                            </small>
                        </div>
                    {/each}
                    {#if !filteredHistory.length}
                        <EmptyState title="No matching requests" />
                    {/if}
                </div>
            {:else}
                <EmptyState
                    title="No request history"
                    hint="Resolved ticket requests will appear here"
                />
            {/if}
        {/if}
    </Loadable>
</div>

<Modal isOpen={!!denyModalRequest} toggle={() => denyModalRequest = undefined}>
    <ModalBody>
        {#if denyError}
            <Alert color="danger">{denyError}</Alert>
        {/if}
        {#if denyModalRequest}
            <p>
                Deny request from
                <strong
                    >{userMap.get(denyModalRequest.userId) ?? denyModalRequest.userId}</strong
                >
                to
                <strong
                    >{targetMap.get(denyModalRequest.targetId) ?? denyModalRequest.targetId}</strong
                >?
            </p>
            <FormGroup floating label="Reason (optional)">
                <input
                    type="text"
                    bind:value={denyReason}
                    class="form-control"
                    placeholder="Why is this being denied?"
                    maxlength="2000"
                >
            </FormGroup>
        {/if}
    </ModalBody>
    <ModalFooter>
        <AsyncButton class="modal-button" color="danger" click={deny}>
            Deny
        </AsyncButton>
        <Button
            class="modal-button"
            color="secondary"
            onclick={() => denyModalRequest = undefined}
        >
            Cancel
        </Button>
    </ModalFooter>
</Modal>

<Modal
    isOpen={!!editingTicket}
    toggle={() => {
        if (!savingEdit) {
            editingTicket = undefined
        }
    }}
>
    <ModalHeader>
        Edit ticket metadata
    </ModalHeader>
    <ModalBody>
        {#if editingTicket}
            <p class="text-muted">
                Access remains for {editingTicket.username} to {editingTicket.target}.
                The ticket secret is unchanged.
            </p>
            <FormGroup floating label="Description">
                <input
                    class="form-control"
                    bind:value={editDescription}
                    maxlength="2000"
                    disabled={savingEdit}
                >
            </FormGroup>
            <FormGroup label="Expiry">
                <div class="form-check">
                    <input
                        id="edit-ticket-set-expiry"
                        class="form-check-input"
                        type="radio"
                        name="edit-ticket-expiry"
                        value="set"
                        bind:group={editExpiryMode}
                        disabled={savingEdit}
                    >
                    <label class="form-check-label" for="edit-ticket-set-expiry">
                        Set Expiry
                    </label>
                </div>
                <div class="form-check">
                    <input
                        id="edit-ticket-no-expiry"
                        class="form-check-input"
                        type="radio"
                        name="edit-ticket-expiry"
                        value="none"
                        bind:group={editExpiryMode}
                        disabled={savingEdit}
                    >
                    <label class="form-check-label" for="edit-ticket-no-expiry">
                        No Expiry
                    </label>
                </div>
            </FormGroup>
            {#if editExpiryMode === 'set'}
                <FormGroup floating label="Expiration date and time">
                    <input
                        class="form-control"
                        type="datetime-local"
                        bind:value={editExpiry}
                        disabled={savingEdit}
                        required
                    >
                </FormGroup>
                <small class="d-block text-muted mb-3">
                    Entered in {timeZone}; saved as UTC.
                </small>
            {:else}
                <p class="text-muted">This ticket has no time-based expiry.</p>
            {/if}
            <FormGroup floating label="Uses remaining (optional)">
                <input
                    class="form-control"
                    type="number"
                    min="0"
                    step="1"
                    bind:value={editUsesLeft}
                    disabled={savingEdit}
                >
            </FormGroup>
            {#if editError}
                <Alert color="danger">{editError}</Alert>
            {/if}
        {/if}
    </ModalBody>
    <ModalFooter>
        <AsyncButton
            class="modal-button"
            color="primary"
            click={saveTicketMetadata}
            disabled={savingEdit}
        >
            Save changes
        </AsyncButton>
        <Button
            class="modal-button"
            color="secondary"
            onclick={() => editingTicket = undefined}
            disabled={savingEdit}
        >
            Cancel
        </Button>
    </ModalFooter>
</Modal>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
    :global(.ticket-actions-toggle) {
        min-width: 34px;
        padding: 2px 8px;
        border: 1px solid var(--bs-border-color);
        color: var(--bs-body-color);
        font-size: 20px;
        line-height: 1.2;
    }
    :global(.ticket-actions-toggle:hover),
    :global(.ticket-actions-toggle:focus) {
        background: var(--bs-tertiary-bg);
        color: var(--bs-body-color);
    }
</style>
