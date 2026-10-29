import {
    Configuration,
    DefaultApi,
    ResponseError,
} from './api-client/dist'

const configuration = new Configuration({
    basePath: '/@warpgate/admin/api',
})

export const api = new DefaultApi(configuration)
export * from './api-client'

export async function updateTicketMetadata(
    id: string,
    metadata: {
        expiry?: Date
        numberOfUses?: number
        description: string
    },
): Promise<void> {
    await api.updateTicketMetadata({
        id,
        updateTicketMetadataRequest: {
            expiry: metadata.expiry,
            numberOfUses: metadata.numberOfUses,
            description: metadata.description,
        },
    })
}

export async function stringifyError(err: ResponseError): Promise<string> {
    return `API error: ${await err.response.text()}`
}
